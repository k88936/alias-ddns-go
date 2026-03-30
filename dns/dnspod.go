package dns

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const (
	recordListAPI   string = "https://dnsapi.cn/Record.List"
	recordModifyURL string = "https://dnsapi.cn/Record.Modify"
	recordCreateAPI string = "https://dnsapi.cn/Record.Create"
	recordRemoveAPI string = "https://dnsapi.cn/Record.Remove"
)

// https://cloud.tencent.com/document/api/302/8516
// Dnspod 腾讯云dns实现
type Dnspod struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}

// DnspodRecord DnspodRecord
type DnspodRecord struct {
	ID      string
	Name    string
	Type    string
	Value   string
	Enabled string
}

// DnspodRecordListResp recordListAPI结果
type DnspodRecordListResp struct {
	DnspodStatus
	Records []DnspodRecord
}

// DnspodStatus DnspodStatus
type DnspodStatus struct {
	Status struct {
		Code    string
		Message string
	}
}

// Init 初始化
func (dnspod *Dnspod) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	dnspod.DNS = dnsConf.DNS
	dnspod.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认600s
		dnspod.TTL = "600"
	} else {
		dnspod.TTL = dnsConf.TTL
	}
	dnspod.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (dnspod *Dnspod) AddUpdateDomainRecords() config.Domains {
	dnspod.addUpdateDomainRecords("A")
	dnspod.addUpdateDomainRecords("AAAA")
	return dnspod.Domains
}

func (dnspod *Dnspod) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = dnspod.Domains.Ipv4Addrs
		domains = dnspod.Domains.Ipv4Domains
	} else {
		ipAddrs = dnspod.Domains.Ipv6Addrs
		domains = dnspod.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		result, err := dnspod.getRecordList(domain, recordType)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range result.Records {
			currentIPs[record.Value] = record.ID
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
			dnspod.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := dnspod.DeleteDomainRecord(recordID); err != nil {
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
func (dnspod *Dnspod) create(domain *config.Domain, recordType string, ipAddr string) {
	params := domain.GetCustomParams()
	params.Set("login_token", dnspod.DNS.ID+","+dnspod.DNS.Secret)
	params.Set("domain", domain.DomainName)
	params.Set("sub_domain", domain.GetSubDomain())
	params.Set("record_type", recordType)
	params.Set("value", ipAddr)
	params.Set("ttl", dnspod.TTL)
	params.Set("format", "json")

	if !params.Has("record_line") {
		params.Set("record_line", "默认")
	}

	status, err := dnspod.request(recordCreateAPI, params)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if status.Status.Code == "1" {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, status.Status.Message)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// DeleteDomainRecord 删除一条域名记录
func (dnspod *Dnspod) DeleteDomainRecord(recordID string) error {
	params := url.Values{}
	params.Set("login_token", dnspod.DNS.ID+","+dnspod.DNS.Secret)
	params.Set("record_id", recordID)
	params.Set("format", "json")

	status, err := dnspod.request(recordRemoveAPI, params)
	if err != nil {
		util.Log("删除记录失败! RecordID: %s, 异常信息: %s", recordID, err)
		return err
	}

	if status.Status.Code == "1" {
		util.Log("删除记录成功! RecordID: %s", recordID)
		return nil
	}

	util.Log("删除记录失败! RecordID: %s, 异常信息: %s", recordID, status.Status.Message)
	return fmt.Errorf("%s", status.Status.Message)
}

// request sends a POST request to the given API with the given values.
func (dnspod *Dnspod) request(apiAddr string, values url.Values) (status DnspodStatus, err error) {
	client := dnspod.httpClient
	resp, err := client.PostForm(
		apiAddr,
		values,
	)

	err = util.GetHTTPResponse(resp, err, &status)

	return
}

// 获得域名记录列表
func (dnspod *Dnspod) getRecordList(domain *config.Domain, typ string) (result DnspodRecordListResp, err error) {

	params := domain.GetCustomParams()
	params.Set("login_token", dnspod.DNS.ID+","+dnspod.DNS.Secret)
	params.Set("domain", domain.DomainName)
	params.Set("record_type", typ)
	params.Set("sub_domain", domain.GetSubDomain())
	params.Set("format", "json")

	client := dnspod.httpClient
	resp, err := client.PostForm(
		recordListAPI,
		params,
	)

	err = util.GetHTTPResponse(resp, err, &result)

	return
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (dnspod *Dnspod) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	result, err := dnspod.getRecordList(domain, recordType)
	if err != nil {
		return err
	}

	for _, record := range result.Records {
		if err := dnspod.DeleteDomainRecord(record.ID); err != nil {
			util.Log("删除记录失败，继续处理")
		}
	}

	return nil
}
