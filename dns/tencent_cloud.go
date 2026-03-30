package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const (
	tencentCloudEndPoint = "https://dnspod.tencentcloudapi.com"
	tencentCloudVersion  = "2021-03-23"
)

// TencentCloud 腾讯云 DNSPod API 3.0 实现
// https://cloud.tencent.com/document/api/1427/56193
type TencentCloud struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// TencentCloudRecord 腾讯云记录
type TencentCloudRecord struct {
	Domain string `json:"Domain"`
	// DescribeRecordList 不需要 SubDomain
	SubDomain string `json:"SubDomain,omitempty"`
	// CreateRecord/ModifyRecord 不需要 Subdomain
	Subdomain  string `json:"Subdomain,omitempty"`
	RecordType string `json:"RecordType"`
	RecordLine string `json:"RecordLine"`
	// DescribeRecordList 不需要 Value
	Value string `json:"Value,omitempty"`
	// CreateRecord/DescribeRecordList 不需要 RecordId
	RecordId int64 `json:"RecordId,omitempty"`
	// DescribeRecordList 不需要 TTL
	TTL int `json:"TTL,omitempty"`
}

// TencentCloudRecordListsResp 获取域名的解析记录列表返回结果
type TencentCloudRecordListsResp struct {
	TencentCloudStatus
	Response struct {
		RecordCountInfo struct {
			TotalCount int `json:"TotalCount"`
		} `json:"RecordCountInfo"`

		RecordList []TencentCloudRecord `json:"RecordList"`
	}
}

// TencentCloudStatus 腾讯云返回状态
// https://cloud.tencent.com/document/product/1427/56192
type TencentCloudStatus struct {
	Response struct {
		Error struct {
			Code    string
			Message string
		}
	}
}

func (tc *TencentCloud) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	tc.DNS = dnsConf.DNS
	tc.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认 600s
		tc.TTL = 600
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			tc.TTL = 600
		} else {
			tc.TTL = ttl
		}
	}
	tc.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新 IPv4/IPv6 记录
func (tc *TencentCloud) AddUpdateDomainRecords() config.Domains {
	tc.addUpdateDomainRecords("A")
	tc.addUpdateDomainRecords("AAAA")
	return tc.Domains
}

func (tc *TencentCloud) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = tc.Domains.Ipv4Addrs
		domains = tc.Domains.Ipv4Domains
	} else {
		ipAddrs = tc.Domains.Ipv6Addrs
		domains = tc.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		result, err := tc.getRecordList(domain, recordType)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range result.Response.RecordList {
			// TencentCloud uses Value field for IP and RecordId (int64) needs conversion
			currentIPs[record.Value] = strconv.FormatInt(record.RecordId, 10)
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
			tc.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := tc.DeleteDomainRecord(recordID); err != nil {
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

// create 添加记录
// CreateRecord https://cloud.tencent.com/document/api/1427/56180
func (tc *TencentCloud) create(domain *config.Domain, recordType string, ipAddr string) {
	record := &TencentCloudRecord{
		Domain:     domain.DomainName,
		SubDomain:  domain.GetSubDomain(),
		RecordType: recordType,
		RecordLine: tc.getRecordLine(domain),
		Value:      ipAddr,
		TTL:        tc.TTL,
	}

	var status TencentCloudStatus
	err := tc.request(
		"CreateRecord",
		record,
		&status,
	)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if status.Response.Error.Code == "" {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, status.Response.Error.Message)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// DeleteDomainRecord 删除单条记录
// DeleteRecord https://cloud.tencent.com/document/api/1427/56179
func (tc *TencentCloud) DeleteDomainRecord(recordID string) error {
	// TODO: TencentCloud has complex signature requirements. Implement later.
	return fmt.Errorf("DeleteDomainRecord not yet implemented for TencentCloud")
}

// getRecordList 获取域名的解析记录列表
// DescribeRecordList https://cloud.tencent.com/document/api/1427/56166
func (tc *TencentCloud) getRecordList(domain *config.Domain, recordType string) (result TencentCloudRecordListsResp, err error) {
	record := TencentCloudRecord{
		Domain:     domain.DomainName,
		Subdomain:  domain.GetSubDomain(),
		RecordType: recordType,
		RecordLine: tc.getRecordLine(domain),
	}
	err = tc.request(
		"DescribeRecordList",
		record,
		&result,
	)

	return
}

// getRecordLine 获取记录线路，为空返回默认
func (tc *TencentCloud) getRecordLine(domain *config.Domain) string {
	if domain.GetCustomParams().Has("RecordLine") {
		return domain.GetCustomParams().Get("RecordLine")
	}
	return "默认"
}

// request 统一请求接口
func (tc *TencentCloud) request(action string, data interface{}, result interface{}) (err error) {
	jsonStr := make([]byte, 0)
	if data != nil {
		jsonStr, _ = json.Marshal(data)
	}
	req, err := http.NewRequest(
		"POST",
		tencentCloudEndPoint,
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TC-Version", tencentCloudVersion)

	util.TencentCloudSigner(tc.DNS.ID, tc.DNS.Secret, req, action, string(jsonStr), util.DnsPod)

	client := tc.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}
