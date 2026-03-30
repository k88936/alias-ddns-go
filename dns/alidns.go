package dns

import (
	"bytes"
	"net/http"
	"net/url"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const (
	alidnsEndpoint string = "https://alidns.aliyuncs.com/"
)

// Alidns Alidns
type Alidns struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}

// AlidnsRecord record
type AlidnsRecord struct {
	DomainName string
	RecordID   string
	Value      string
}

// AlidnsSubDomainRecords 记录
type AlidnsSubDomainRecords struct {
	TotalCount    int
	DomainRecords struct {
		Record []AlidnsRecord
	}
}

// AlidnsResp 修改/添加返回结果
type AlidnsResp struct {
	RecordID  string
	RequestID string
}

// Init 初始化
func (ali *Alidns) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	ali.DNS = dnsConf.DNS
	ali.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		ali.TTL = "600"
	} else {
		ali.TTL = dnsConf.TTL
	}
	ali.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (ali *Alidns) AddUpdateDomainRecords() config.Domains {
	ali.addUpdateDomainRecords("A")
	ali.addUpdateDomainRecords("AAAA")
	return ali.Domains
}

func (ali *Alidns) addUpdateDomainRecords(recordType string) {

	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = ali.Domains.Ipv4Addrs
		domains = ali.Domains.Ipv4Domains
	} else {
		ipAddrs = ali.Domains.Ipv6Addrs
		domains = ali.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		var records AlidnsSubDomainRecords
		params := domain.GetCustomParams()
		params.Set("Action", "DescribeSubDomainRecords")
		params.Set("DomainName", domain.DomainName)
		params.Set("SubDomain", domain.GetFullDomain())
		params.Set("Type", recordType)
		err := ali.request(params, &records)

		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range records.DomainRecords.Record {
			currentIPs[record.Value] = record.RecordID
			util.Log("current value: %s", record.Value)
		}

		// 步骤3：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

		// Log deletion plans
		for _, recordID := range compareResult.ToDelete {
			util.Log("  将删除多余记录: %s (RecordID: %s)", currentIPs[recordID], recordID)
		}

		// Log creation plans
		for _, ip := range compareResult.ToCreate {
			util.Log("  将创建新记录: %s", ip)
		}

		createdCount := 0
		for _, ip := range compareResult.ToCreate {
			ali.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := ali.DeleteDomainRecord(recordID); err != nil {
				util.Log("删除记录失败，继续处理")
			} else {
				deletedCount++
			}
		}

		// 步骤6：计算保持不变的记录数
		unchangedCount := 0
		for ip := range compareResult.DesiredIPs {
			if _, exists := currentIPs[ip]; exists {
				unchangedCount++
			}
		}

		// 总结更新结果
		if len(compareResult.ToDelete) == 0 && len(compareResult.ToCreate) == 0 {
			util.Log("域名 %s 的所有记录均无变化", domain)
			domain.UpdateStatus = config.UpdatedNothing
		} else {
			util.Log("域名 %s 更新完成: 保持 %d 条, 新增 %d 条, 删除 %d 条",
				domain, unchangedCount, createdCount, deletedCount)
			if createdCount > 0 || deletedCount > 0 {
				domain.UpdateStatus = config.UpdatedSuccess
			} else {
				domain.UpdateStatus = config.UpdatedFailed
			}
		}
	}
}

// 创建
func (ali *Alidns) create(domain *config.Domain, recordType string, ipAddr string) {
	params := domain.GetCustomParams()
	params.Set("Action", "AddDomainRecord")
	params.Set("DomainName", domain.DomainName)
	params.Set("RR", domain.GetSubDomain())
	params.Set("Type", recordType)
	params.Set("Value", ipAddr)
	params.Set("TTL", ali.TTL)

	var result AlidnsResp
	err := ali.request(params, &result)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if result.RecordID != "" {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, "返回RecordId为空")
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// DeleteDomainRecord 删除单条域名记录 https://help.aliyun.com/document_detail/29776.html?spm=a2c4g.11186623.6.672.715a45caji9dMA
func (ali *Alidns) DeleteDomainRecord(recordID string) error {
	params := url.Values{}
	params.Set("Action", "DeleteDomainRecord")
	params.Set("RecordId", recordID)

	var result AlidnsResp
	err := ali.request(params, &result)

	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	util.Log("成功删除记录ID: %s", recordID)
	return nil
}

// request 统一请求接口
func (ali *Alidns) request(params url.Values, result interface{}) (err error) {
	method := http.MethodGet
	util.AliyunSigner(ali.DNS.ID, ali.DNS.Secret, &params, method, "2015-01-09")

	req, err := http.NewRequest(
		method,
		alidnsEndpoint,
		bytes.NewBuffer(nil),
	)
	req.URL.RawQuery = params.Encode()

	if err != nil {
		return
	}

	client := ali.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}
