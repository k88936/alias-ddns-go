package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

type Vercel struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

type ListExistingRecordsResponse struct {
	Records []Record `json:"records"`
}

type Record struct {
	ID        string  `json:"id"` // 记录ID
	Slug      string  `json:"slug"`
	Name      string  `json:"name"`  // 记录名称
	Type      string  `json:"type"`  // 记录类型
	Value     string  `json:"value"` // 记录值
	Creator   string  `json:"creator"`
	Created   int64   `json:"created"`
	Updated   int64   `json:"updated"`
	CreatedAt int64   `json:"createdAt"`
	UpdatedAt int64   `json:"updatedAt"`
	TTL       int64   `json:"ttl"`
	Comment   *string `json:"comment,omitempty"`
}

func (v *Vercel) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	v.DNS = dnsConf.DNS
	v.Domains.InitFromConfig(dnsConf)

	// Must be greater than 60
	ttl, err := strconv.Atoi(dnsConf.TTL)
	if err != nil {
		ttl = 60
	}
	if ttl < 60 {
		ttl = 60
	}
	v.TTL = ttl
	v.httpClient = dnsConf.GetHTTPClient()
}

func (v *Vercel) AddUpdateDomainRecords() (domains config.Domains) {
	v.addUpdateDomainRecords("A")
	v.addUpdateDomainRecords("AAAA")
	return v.Domains
}

func (v *Vercel) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = v.Domains.Ipv4Addrs
		domains = v.Domains.Ipv4Domains
	} else {
		ipAddrs = v.Domains.Ipv6Addrs
		domains = v.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		records, err := v.listExistingRecords(domain)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合 (map[IP]RecordID)
		currentIPs := make(map[string]string)
		for _, record := range records {
			if record.Name == domain.SubDomain && record.Type == recordType {
				currentIPs[strings.ToLower(record.Value)] = record.ID
				util.Log("current value: %s", record.Value)
			}
		}

		// 标准化期望的IP地址为小写
		normalizedIPAddrs := make([]string, len(ipAddrs))
		for i, ip := range ipAddrs {
			normalizedIPAddrs[i] = strings.ToLower(ip)
		}

		// 步骤3：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, normalizedIPAddrs)

		// Log deletion plans
		for _, recordID := range compareResult.ToDelete {
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
			err := v.createRecord(domain, recordType, ip)
			if err == nil {
				util.Log("创建域名解析 %s 成功! IP: %s", domain, ip)
				createdCount++
			} else {
				util.Log("创建域名解析 %s 失败! IP: %s, 异常信息: %s", domain, ip, err)
			}
		}

		// 步骤5：删除多余记录
		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := v.DeleteDomainRecord(recordID); err != nil {
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

func (v *Vercel) listExistingRecords(domain *config.Domain) (records []Record, err error) {
	var result ListExistingRecordsResponse
	err = v.request(http.MethodGet, "https://api.vercel.com/v4/domains/"+domain.DomainName+"/records", nil, &result)
	if err != nil {
		return
	}
	records = result.Records
	return
}

func (v *Vercel) createRecord(domain *config.Domain, recordType string, recordValue string) (err error) {
	err = v.request(http.MethodPost, "https://api.vercel.com/v2/domains/"+domain.DomainName+"/records", map[string]interface{}{
		"name":    domain.SubDomain,
		"type":    recordType,
		"value":   recordValue,
		"ttl":     v.TTL,
		"comment": "Created by ddns-go",
	}, nil)
	return
}

func (v *Vercel) updateRecord(record *Record, recordType string, recordValue string) (err error) {
	err = v.request(http.MethodPatch, "https://api.vercel.com/v1/domains/records/"+record.ID, map[string]interface{}{
		"type":  recordType,
		"value": recordValue,
		"ttl":   v.TTL,
	}, nil)
	return
}

func (v *Vercel) request(method, api string, data, result interface{}) (err error) {
	var payload []byte
	if data != nil {
		payload, _ = json.Marshal(data)
	}

	// 如果设置了 ExtParam (TeamId)，添加查询参数
	if v.DNS.ExtParam != "" {
		if strings.Contains(api, "?") {
			api = api + "&teamId=" + v.DNS.ExtParam
		} else {
			api = api + "?teamId=" + v.DNS.ExtParam
		}
	}

	req, err := http.NewRequest(
		method,
		api,
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+v.DNS.Secret)
	req.Header.Set("Content-Type", "application/json")

	client := v.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("Vercel API returned status code %d", resp.StatusCode)
	}
	if result != nil {
		err = util.GetHTTPResponse(resp, err, result)
	}
	return
}

// DeleteDomainRecord 删除单条DNS记录
func (v *Vercel) DeleteDomainRecord(recordID string) error {
	err := v.request(http.MethodDelete, "https://api.vercel.com/v2/domains/records/"+recordID, nil, nil)
	if err != nil {
		util.Log("删除记录 %s 失败: %s", recordID, err)
		return err
	}
	util.Log("删除记录 %s 成功", recordID)
	return nil
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (ver *Vercel) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Vercel provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for Vercel provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
