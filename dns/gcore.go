package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const gcoreAPIEndpoint = "https://api.gcore.com/dns/v2"

// Gcore Gcore DNS实现
type Gcore struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// GcoreZoneResponse zones返回结果
type GcoreZoneResponse struct {
	Zones       []GcoreZone `json:"zones"`
	TotalAmount int         `json:"total_amount"`
}

// GcoreZone 域名信息
type GcoreZone struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// GcoreRRSetListResponse RRSet列表返回结果
type GcoreRRSetListResponse struct {
	RRSets      []GcoreRRSet `json:"rrsets"`
	TotalAmount int          `json:"total_amount"`
}

// GcoreRRSet RRSet记录实体
type GcoreRRSet struct {
	Name            string                 `json:"name"`
	Type            string                 `json:"type"`
	TTL             int                    `json:"ttl"`
	ResourceRecords []GcoreResourceRecord  `json:"resource_records"`
	Meta            map[string]interface{} `json:"meta,omitempty"`
}

// GcoreResourceRecord 资源记录
type GcoreResourceRecord struct {
	Content []interface{}          `json:"content"`
	Enabled bool                   `json:"enabled"`
	ID      int                    `json:"id,omitempty"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// GcoreInputRRSet 输入的RRSet
type GcoreInputRRSet struct {
	TTL             int                        `json:"ttl"`
	ResourceRecords []GcoreInputResourceRecord `json:"resource_records"`
	Meta            map[string]interface{}     `json:"meta,omitempty"`
}

// GcoreInputResourceRecord 输入的资源记录
type GcoreInputResourceRecord struct {
	Content []interface{}          `json:"content"`
	Enabled bool                   `json:"enabled"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

// Init 初始化
func (gc *Gcore) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	gc.DNS = dnsConf.DNS
	gc.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认 120 秒（免费版最低值）
		gc.TTL = 120
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			gc.TTL = 120
		} else {
			gc.TTL = ttl
		}
	}
	gc.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新 IPv4 / IPv6 记录
func (gc *Gcore) AddUpdateDomainRecords() config.Domains {
	gc.addUpdateDomainRecords("A")
	gc.addUpdateDomainRecords("AAAA")
	return gc.Domains
}

func (gc *Gcore) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = gc.Domains.Ipv4Addrs
		domains = gc.Domains.Ipv4Domains
	} else {
		ipAddrs = gc.Domains.Ipv6Addrs
		domains = gc.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取zone信息
		zoneInfo, err := gc.getZoneByDomain(domain)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		if zoneInfo == nil {
			util.Log("在DNS服务商中未找到根域名: %s", domain.DomainName)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：查询现有记录
		existingRecord, err := gc.getRRSet(zoneInfo.Name, domain.GetSubDomain(), recordType)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤3：构建当前IP集合 (Gcore uses RRSet with multiple ResourceRecords)
		currentIPs := make(map[string]string) // map[IP]recordIdentifier
		if existingRecord != nil {
			for _, rr := range existingRecord.ResourceRecords {
				if len(rr.Content) > 0 {
					ip := fmt.Sprintf("%v", rr.Content[0])
					// Gcore RRSet doesn't have individual record IDs per IP
					// Use the IP itself as identifier for the comparison
					currentIPs[ip] = ip
					util.Log("current value: %s", ip)
				}
			}
		}

		// 步骤4：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

		// Log deletion plans
		for _, ip := range compareResult.ToDelete {
			util.Log("  将删除多余记录: %s", ip)
		}

		// Log creation plans
		for _, ip := range compareResult.ToCreate {
			util.Log("  将创建新记录: %s", ip)
		}

		// 步骤5：创建新记录（先创建，后删除，避免服务中断）
		createdCount := 0
		for _, ip := range compareResult.ToCreate {
			if gc.createOrUpdateRecord(zoneInfo.Name, domain, recordType, ip, existingRecord, compareResult) {
				createdCount++
			}
		}

		// 步骤6：删除多余记录
		deletedCount := 0
		for _, ip := range compareResult.ToDelete {
			if gc.deleteRecordIP(zoneInfo.Name, domain, recordType, ip, existingRecord, compareResult) {
				deletedCount++
			}
		}

		// 步骤7：计算保持不变的记录数
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

// 获取域名对应的Zone信息
func (gc *Gcore) getZoneByDomain(domain *config.Domain) (*GcoreZone, error) {
	var result GcoreZoneResponse
	params := url.Values{}
	params.Set("name", domain.DomainName)

	err := gc.request(
		"GET",
		fmt.Sprintf("%s/zones?%s", gcoreAPIEndpoint, params.Encode()),
		nil,
		&result,
	)

	if err != nil {
		return nil, err
	}

	if len(result.Zones) > 0 {
		return &result.Zones[0], nil
	}

	return nil, nil
}

// 获取指定的RRSet记录
func (gc *Gcore) getRRSet(zoneName, recordName, recordType string) (*GcoreRRSet, error) {
	var result GcoreRRSetListResponse

	err := gc.request(
		"GET",
		fmt.Sprintf("%s/zones/%s/rrsets", gcoreAPIEndpoint, zoneName),
		nil,
		&result,
	)

	if err != nil {
		return nil, err
	}

	// 查找匹配的记录
	fullRecordName := recordName
	if recordName != "" && recordName != "@" {
		fullRecordName = recordName + "." + zoneName
	} else {
		fullRecordName = zoneName
	}

	for _, rrset := range result.RRSets {
		if rrset.Name == fullRecordName && rrset.Type == recordType {
			return &rrset, nil
		}
	}

	return nil, nil
}

// createOrUpdateRecord 创建或更新记录（添加新IP到RRSet）
func (gc *Gcore) createOrUpdateRecord(zoneName string, domain *config.Domain, recordType string, newIP string, existingRecord *GcoreRRSet, compareResult *util.DNSCompareResult) bool {
	recordName := domain.GetSubDomain()
	if recordName == "" || recordName == "@" {
		recordName = zoneName
	} else {
		recordName = recordName + "." + zoneName
	}

	// 构建新的ResourceRecords列表
	var resourceRecords []GcoreInputResourceRecord

	// 保留现有的IP（除了要删除的）
	if existingRecord != nil {
		for _, rr := range existingRecord.ResourceRecords {
			if len(rr.Content) > 0 {
				ip := fmt.Sprintf("%v", rr.Content[0])
				// 只保留期望保留的IP
				if compareResult.DesiredIPs[ip] && ip != newIP {
					resourceRecords = append(resourceRecords, GcoreInputResourceRecord{
						Content: []interface{}{ip},
						Enabled: true,
					})
				}
			}
		}
	}

	// 添加新IP
	resourceRecords = append(resourceRecords, GcoreInputResourceRecord{
		Content: []interface{}{newIP},
		Enabled: true,
	})

	inputRRSet := GcoreInputRRSet{
		TTL:             gc.TTL,
		ResourceRecords: resourceRecords,
	}

	var result interface{}
	method := "POST"
	if existingRecord != nil {
		method = "PUT"
	}

	err := gc.request(
		method,
		fmt.Sprintf("%s/zones/%s/%s/%s", gcoreAPIEndpoint, zoneName, recordName, recordType),
		inputRRSet,
		&result,
	)

	if err != nil {
		util.Log("添加域名解析 %s 失败! IP: %s, 异常信息: %s", domain, newIP, err)
		domain.UpdateStatus = config.UpdatedFailed
		return false
	}

	util.Log("添加域名解析 %s 成功! IP: %s", domain, newIP)
	return true
}

// deleteRecordIP 从RRSet中删除指定IP
func (gc *Gcore) deleteRecordIP(zoneName string, domain *config.Domain, recordType string, deleteIP string, existingRecord *GcoreRRSet, compareResult *util.DNSCompareResult) bool {
	if existingRecord == nil {
		return false
	}

	recordName := domain.GetSubDomain()
	if recordName == "" || recordName == "@" {
		recordName = zoneName
	} else {
		recordName = recordName + "." + zoneName
	}

	// 构建保留的ResourceRecords列表（排除要删除的IP）
	var resourceRecords []GcoreInputResourceRecord
	for _, rr := range existingRecord.ResourceRecords {
		if len(rr.Content) > 0 {
			ip := fmt.Sprintf("%v", rr.Content[0])
			// 只保留期望保留的IP（排除要删除的）
			if compareResult.DesiredIPs[ip] {
				resourceRecords = append(resourceRecords, GcoreInputResourceRecord{
					Content: []interface{}{ip},
					Enabled: true,
				})
			}
		}
	}

	// 如果没有剩余记录，删除整个RRSet
	if len(resourceRecords) == 0 {
		var result interface{}
		err := gc.request(
			"DELETE",
			fmt.Sprintf("%s/zones/%s/%s/%s", gcoreAPIEndpoint, zoneName, recordName, recordType),
			nil,
			&result,
		)

		if err != nil {
			util.Log("删除域名记录 %s 失败! IP: %s, 异常信息: %s", domain, deleteIP, err)
			return false
		}

		util.Log("删除域名记录 %s 成功! IP: %s", domain, deleteIP)
		return true
	}

	// 否则更新RRSet（移除指定IP）
	inputRRSet := GcoreInputRRSet{
		TTL:             gc.TTL,
		ResourceRecords: resourceRecords,
	}

	var result interface{}
	err := gc.request(
		"PUT",
		fmt.Sprintf("%s/zones/%s/%s/%s", gcoreAPIEndpoint, zoneName, recordName, recordType),
		inputRRSet,
		&result,
	)

	if err != nil {
		util.Log("删除域名记录 %s 失败! IP: %s, 异常信息: %s", domain, deleteIP, err)
		return false
	}

	util.Log("删除域名记录 %s 成功! IP: %s", domain, deleteIP)
	return true
}

// request 统一请求接口
func (gc *Gcore) request(method string, url string, data interface{}, result interface{}) (err error) {
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

	req.Header.Set("Authorization", "APIKey "+gc.DNS.Secret)
	req.Header.Set("Content-Type", "application/json")

	client := gc.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}

// DeleteDomainRecord 删除单条域名记录
func (gc *Gcore) DeleteDomainRecord(recordID string) error {
	// recordID format: "zoneName/recordName/recordType"
	parts := url.QueryEscape(recordID)
	_ = parts // recordID contains "zoneName/recordName/recordType"

	var result interface{}
	err := gc.request(
		"DELETE",
		fmt.Sprintf("%s/zones/%s", gcoreAPIEndpoint, recordID),
		nil,
		&result,
	)

	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	util.Log("成功删除记录ID: %s", recordID)
	return nil
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (gco *Gcore) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Gcore provider does not support alias mode. Use 'alidns' provider instead.")
}
