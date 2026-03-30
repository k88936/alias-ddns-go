package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const (
	porkbunEndpoint string = "https://api.porkbun.com/api/json/v3/dns"
)

type Porkbun struct {
	DNSConfig  config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}
type PorkbunDomainRecord struct {
	ID      *string `json:"id"`      // record ID
	Name    *string `json:"name"`    // subdomain
	Type    *string `json:"type"`    // record type, e.g. A AAAA CNAME
	Content *string `json:"content"` // value
	Ttl     *string `json:"ttl"`     // default 300
}

type PorkbunResponse struct {
	Status string `json:"status"`
}

type PorkbunDomainQueryResponse struct {
	*PorkbunResponse
	Records []PorkbunDomainRecord `json:"records"`
}

type PorkbunApiKey struct {
	AccessKey string `json:"apikey"`
	SecretKey string `json:"secretapikey"`
}

type PorkbunDomainCreateOrUpdateVO struct {
	*PorkbunApiKey
	*PorkbunDomainRecord
}

// Init 初始化
func (pb *Porkbun) Init(conf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	pb.DNSConfig = conf.DNS
	pb.Domains.InitFromConfig(conf)
	if conf.TTL == "" {
		// 默认600s
		pb.TTL = "600"
	} else {
		pb.TTL = conf.TTL
	}
	pb.httpClient = conf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (pb *Porkbun) AddUpdateDomainRecords() config.Domains {
	pb.addUpdateDomainRecords("A")
	pb.addUpdateDomainRecords("AAAA")
	return pb.Domains
}

func (pb *Porkbun) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = pb.Domains.Ipv4Addrs
		domains = pb.Domains.Ipv4Domains
	} else {
		ipAddrs = pb.Domains.Ipv6Addrs
		domains = pb.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		var record PorkbunDomainQueryResponse
		err := pb.request(
			porkbunEndpoint+fmt.Sprintf("/retrieveByNameType/%s/%s/%s", domain.DomainName, recordType, domain.SubDomain),
			&PorkbunApiKey{
				AccessKey: pb.DNSConfig.ID,
				SecretKey: pb.DNSConfig.Secret,
			},
			&record,
		)

		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		if record.Status != "SUCCESS" {
			util.Log("在DNS服务商中未找到根域名: %s", domain.DomainName)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, rec := range record.Records {
			if rec.Content != nil && rec.ID != nil {
				currentIPs[*rec.Content] = *rec.ID
				util.Log("current value: %s", *rec.Content)
			}
		}

		// 步骤3：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

		// Log deletion plans
		for _, recordID := range compareResult.ToDelete {
			// Find the IP for this recordID
			for ip, id := range currentIPs {
				if id == recordID {
					util.Log("  将删除多余记录: %s (RecordID: %s)", ip, recordID)
					break
				}
			}
		}

		// Log creation plans
		for _, ip := range compareResult.ToCreate {
			util.Log("  将创建新记录: %s", ip)
		}

		// 步骤4：创建新记录
		createdCount := 0
		for _, ip := range compareResult.ToCreate {
			pb.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		// 步骤5：删除多余记录
		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := pb.DeleteDomainRecord(recordID, domain.DomainName); err != nil {
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
func (pb *Porkbun) create(domain *config.Domain, recordType string, ipAddr string) {
	var response PorkbunResponse

	err := pb.request(
		porkbunEndpoint+fmt.Sprintf("/create/%s", domain.DomainName),
		&PorkbunDomainCreateOrUpdateVO{
			PorkbunApiKey: &PorkbunApiKey{
				AccessKey: pb.DNSConfig.ID,
				SecretKey: pb.DNSConfig.Secret,
			},
			PorkbunDomainRecord: &PorkbunDomainRecord{
				Name:    &domain.SubDomain,
				Type:    &recordType,
				Content: &ipAddr,
				Ttl:     &pb.TTL,
			},
		},
		&response,
	)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if response.Status == "SUCCESS" {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, response.Status)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// DeleteDomainRecord 删除域名记录
func (pb *Porkbun) DeleteDomainRecord(recordID string, domainName string) error {
	var response PorkbunResponse

	err := pb.request(
		porkbunEndpoint+fmt.Sprintf("/delete/%s/%s", domainName, recordID),
		&PorkbunApiKey{
			AccessKey: pb.DNSConfig.ID,
			SecretKey: pb.DNSConfig.Secret,
		},
		&response,
	)

	if err != nil {
		util.Log("删除域名解析记录失败! RecordID: %s, 异常信息: %s", recordID, err)
		return err
	}

	if response.Status == "SUCCESS" {
		util.Log("删除域名解析记录成功! RecordID: %s", recordID)
		return nil
	} else {
		util.Log("删除域名解析记录失败! RecordID: %s, 异常信息: %s", recordID, response.Status)
		return fmt.Errorf("delete failed: %s", response.Status)
	}
}

// request 统一请求接口
func (pb *Porkbun) request(url string, data interface{}, result interface{}) (err error) {
	jsonStr := make([]byte, 0)
	if data != nil {
		jsonStr, _ = json.Marshal(data)
	}
	req, err := http.NewRequest(
		"POST",
		url,
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := pb.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (por *Porkbun) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Porkbun provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for Porkbun provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
