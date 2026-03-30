package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const zonesAPI = "https://api.cloudflare.com/client/v4/zones"

// Cloudflare Cloudflare实现
type Cloudflare struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// CloudflareZonesResp cloudflare zones返回结果
type CloudflareZonesResp struct {
	CloudflareStatus
	Result []struct {
		ID     string
		Name   string
		Status string
		Paused bool
	}
}

// CloudflareRecordsResp records
type CloudflareRecordsResp struct {
	CloudflareStatus
	Result []CloudflareRecord
}

// CloudflareRecord 记录实体
type CloudflareRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
	Comment string `json:"comment"`
}

// CloudflareStatus 公共状态
type CloudflareStatus struct {
	Success  bool
	Messages []string
}

func (cf *Cloudflare) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	cf.DNS = dnsConf.DNS
	cf.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		cf.TTL = 1
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			cf.TTL = 1
		} else {
			cf.TTL = ttl
		}
	}
	cf.httpClient = dnsConf.GetHTTPClient()
}

func (cf *Cloudflare) AddUpdateDomainRecords() config.Domains {
	cf.addUpdateDomainRecords("A")
	cf.addUpdateDomainRecords("AAAA")
	return cf.Domains
}

func (cf *Cloudflare) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = cf.Domains.Ipv4Addrs
		domains = cf.Domains.Ipv4Domains
	} else {
		ipAddrs = cf.Domains.Ipv6Addrs
		domains = cf.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// get zone
		result, err := cf.getZones(domain)

		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		if len(result.Result) == 0 {
			util.Log("在DNS服务商中未找到根域名: %s", domain.DomainName)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		params := url.Values{}
		params.Set("type", recordType)
		// The name of DNS records in Cloudflare API expects Punycode.
		//
		// See: cloudflare/cloudflare-go#690
		params.Set("name", domain.ToASCII())
		params.Set("per_page", "50")
		// Add a comment only if it exists
		if c := domain.GetCustomParams().Get("comment"); c != "" {
			params.Set("comment", c)
		}

		zoneID := result.Result[0].ID

		var records CloudflareRecordsResp
		// getDomains 最多更新前50条
		err = cf.request(
			"GET",
			fmt.Sprintf(zonesAPI+"/%s/dns_records?%s", zoneID, params.Encode()),
			nil,
			&records,
		)

		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		if !records.Success {
			util.Log("查询域名信息发生异常! %s", strings.Join(records.Messages, ", "))
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range records.Result {
			// Store as "zoneID/recordID" for deletion
			currentIPs[record.Content] = zoneID + "/" + record.ID
			util.Log("current value: %s", record.Content)
		}

		// 步骤3：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

		// Log deletion plans
		for _, recordID := range compareResult.ToDelete {
			// Find IP for this recordID
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
			cf.create(zoneID, domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		// 步骤5：删除多余记录
		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := cf.DeleteDomainRecord(recordID); err != nil {
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

func (cf *Cloudflare) create(zoneID string, domain *config.Domain, recordType string, ipAddr string) {
	record := &CloudflareRecord{
		Type:    recordType,
		Name:    domain.ToASCII(),
		Content: ipAddr,
		Proxied: false,
		TTL:     cf.TTL,
		Comment: domain.GetCustomParams().Get("comment"),
	}
	record.Proxied = domain.GetCustomParams().Get("proxied") == "true"
	var status CloudflareStatus
	err := cf.request(
		"POST",
		fmt.Sprintf(zonesAPI+"/%s/dns_records", zoneID),
		record,
		&status,
	)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if status.Success {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, strings.Join(status.Messages, ", "))
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// 获得域名记录列表
func (cf *Cloudflare) getZones(domain *config.Domain) (result CloudflareZonesResp, err error) {
	params := url.Values{}
	params.Set("name", domain.DomainName)
	params.Set("status", "active")
	params.Set("per_page", "50")

	err = cf.request(
		"GET",
		fmt.Sprintf(zonesAPI+"?%s", params.Encode()),
		nil,
		&result,
	)

	return
}

// request 统一请求接口
func (cf *Cloudflare) request(method string, url string, data interface{}, result interface{}) (err error) {
	jsonStr := make([]byte, 0)
	if data != nil {
		jsonStr, _ = json.Marshal(data)
	}
	req, err := http.NewRequest(
		method,
		url,
		bytes.NewBuffer(jsonStr),
	)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+cf.DNS.Secret)
	req.Header.Set("Content-Type", "application/json")

	client := cf.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}

// DeleteDomainRecord 删除单条域名记录
func (cf *Cloudflare) DeleteDomainRecord(recordID string) error {
	// recordID format: "zoneID/recordID"
	parts := strings.Split(recordID, "/")
	if len(parts) != 2 {
		err := fmt.Errorf("invalid recordID format: %s", recordID)
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	zoneID := parts[0]
	recID := parts[1]

	var status CloudflareStatus
	err := cf.request(
		"DELETE",
		fmt.Sprintf(zonesAPI+"/%s/dns_records/%s", zoneID, recID),
		nil,
		&status,
	)

	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	if !status.Success {
		err = fmt.Errorf("%s", strings.Join(status.Messages, ", "))
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	util.Log("成功删除记录ID: %s", recordID)
	return nil
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (cf *Cloudflare) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Cloudflare provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for Cloudflare provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
