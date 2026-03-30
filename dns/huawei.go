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

const (
	huaweicloudEndpoint string = "https://dns.myhuaweicloud.com"
)

// https://support.huaweicloud.com/api-dns/dns_api_64001.html
// Huaweicloud Huaweicloud
type Huaweicloud struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// HuaweicloudZonesResp zones response
type HuaweicloudZonesResp struct {
	Zones []struct {
		ID         string
		Name       string
		Recordsets []HuaweicloudRecordsets
	}
}

// HuaweicloudRecordsResp 记录返回结果
type HuaweicloudRecordsResp struct {
	Recordsets []HuaweicloudRecordsets
}

// HuaweicloudRecordsets 记录
type HuaweicloudRecordsets struct {
	ID      string
	Name    string `json:"name"`
	ZoneID  string `json:"zone_id"`
	Status  string
	Type    string   `json:"type"`
	TTL     int      `json:"ttl"`
	Records []string `json:"records"`
	Weight  int      `json:"weight"`
}

// Init 初始化
func (hw *Huaweicloud) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	hw.DNS = dnsConf.DNS
	hw.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认300s
		hw.TTL = 300
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			hw.TTL = 300
		} else {
			hw.TTL = ttl
		}
	}
	hw.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (hw *Huaweicloud) AddUpdateDomainRecords() config.Domains {
	hw.addUpdateDomainRecords("A")
	hw.addUpdateDomainRecords("AAAA")
	return hw.Domains
}

func (hw *Huaweicloud) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = hw.Domains.Ipv4Addrs
		domains = hw.Domains.Ipv4Domains
	} else {
		ipAddrs = hw.Domains.Ipv6Addrs
		domains = hw.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		customParams := domain.GetCustomParams()
		params := url.Values{}
		params.Set("name", domain.String())
		params.Set("type", recordType)

		var currentIPs map[string]string
		var recordsetID string
		var zoneID string

		// 如果有精准匹配
		// 详见 查询记录集 https://support.huaweicloud.com/api-dns/dns_api_64002.html
		if customParams.Has("zone_id") && customParams.Has("recordset_id") {
			var record HuaweicloudRecordsets
			err := hw.request(
				"GET",
				fmt.Sprintf(huaweicloudEndpoint+"/v2.1/zones/%s/recordsets/%s", customParams.Get("zone_id"), customParams.Get("recordset_id")),
				params,
				&record,
			)

			if err != nil {
				util.Log("查询域名信息发生异常！ %s", err)
				domain.UpdateStatus = config.UpdatedFailed
				continue
			}

			currentIPs = make(map[string]string)
			for _, ip := range record.Records {
				currentIPs[ip] = record.ID
				util.Log("current value: %s", ip)
			}
			recordsetID = record.ID
			zoneID = record.ZoneID

		} else { // 没有精准匹配，则支持更多的查询参数。详见 查询租户记录集列表 https://support.huaweicloud.com/api-dns/dns_api_64003.html
			// 复制所有自定义参数
			util.CopyUrlParams(customParams, params, nil)
			// 参数名修正
			if params.Has("recordset_id") {
				params.Set("id", params.Get("recordset_id"))
				params.Del("recordset_id")
			}

			var records HuaweicloudRecordsResp
			err := hw.request(
				"GET",
				huaweicloudEndpoint+"/v2.1/recordsets",
				params,
				&records,
			)

			if err != nil {
				util.Log("查询域名信息发生异常! %s", err)
				domain.UpdateStatus = config.UpdatedFailed
				continue
			}

			currentIPs = make(map[string]string)
			find := false
			for _, record := range records.Recordsets {
				// 名称相同才更新。华为云默认是模糊搜索
				if record.Name == domain.String()+"." {
					for _, ip := range record.Records {
						currentIPs[ip] = record.ID
						util.Log("current value: %s", ip)
					}
					recordsetID = record.ID
					zoneID = record.ZoneID
					find = true
					break
				}
			}

			if !find {
				thIdParamName := ""
				if customParams.Has("id") {
					thIdParamName = "id"
				} else if customParams.Has("recordset_id") {
					thIdParamName = "recordset_id"
				}

				if thIdParamName != "" {
					util.Log("域名 %s 解析未找到，且因添加了参数 %s=%s 导致无法创建。本次更新已被忽略", domain, thIdParamName, customParams.Get(thIdParamName))
					domain.UpdateStatus = config.UpdatedFailed
					continue
				}

				// 新增记录集（包含所有IPs）
				hw.createRecordset(domain, recordType, ipAddrs)
				continue
			}
		}

		// 步骤2：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

		// Log deletion plans
		for _, ip := range compareResult.ToDelete {
			util.Log("  将删除多余记录: %s", ip)
		}

		// Log creation plans
		for _, ip := range compareResult.ToCreate {
			util.Log("  将添加新记录: %s", ip)
		}

		// 步骤3：如果有变更，更新整个记录集
		if len(compareResult.ToDelete) > 0 || len(compareResult.ToCreate) > 0 {
			// 构建新的记录列表
			newRecords := make([]string, 0, len(ipAddrs))
			for _, ip := range ipAddrs {
				newRecords = append(newRecords, ip)
			}

			// 更新整个记录集
			if err := hw.updateRecordset(domain, zoneID, recordsetID, recordType, newRecords); err != nil {
				util.Log("更新域名解析失败: %s", err)
				domain.UpdateStatus = config.UpdatedFailed
			} else {
				unchangedCount := 0
				for ip := range compareResult.DesiredIPs {
					if _, exists := currentIPs[ip]; exists {
						unchangedCount++
					}
				}
				util.Log("域名 %s 更新完成: 保持 %d 条, 新增 %d 条, 删除 %d 条",
					domain, unchangedCount, len(compareResult.ToCreate), len(compareResult.ToDelete))
				domain.UpdateStatus = config.UpdatedSuccess
			}
		} else {
			util.Log("域名 %s 的所有记录均无变化", domain)
			domain.UpdateStatus = config.UpdatedNothing
		}
	}
}

// createRecordset 创建记录集（包含所有IPs）
func (hw *Huaweicloud) createRecordset(domain *config.Domain, recordType string, ipAddrs []string) {
	zone, err := hw.getZones(domain)
	if err != nil {
		util.Log("查询域名信息发生异常! %s", err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if len(zone.Zones) == 0 {
		util.Log("在DNS服务商中未找到根域名: %s", domain.DomainName)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	zoneID := zone.Zones[0].ID
	for _, z := range zone.Zones {
		if z.Name == domain.DomainName+"." {
			zoneID = z.ID
			break
		}
	}

	record := &HuaweicloudRecordsets{
		Type:    recordType,
		Name:    domain.String() + ".",
		Records: ipAddrs,
		TTL:     hw.TTL,
		Weight:  1,
	}
	var result HuaweicloudRecordsets
	err = hw.request(
		"POST",
		fmt.Sprintf(huaweicloudEndpoint+"/v2.1/zones/%s/recordsets", zoneID),
		record,
		&result,
	)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if len(result.Records) > 0 {
		util.Log("新增域名解析 %s 成功! IPs: %v", domain, result.Records)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, result.Status)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// updateRecordset 更新记录集
func (hw *Huaweicloud) updateRecordset(domain *config.Domain, zoneID, recordsetID, recordType string, records []string) error {
	var request = make(map[string]interface{})
	request["name"] = domain.String() + "."
	request["type"] = recordType
	request["records"] = records
	request["ttl"] = hw.TTL

	var result HuaweicloudRecordsets

	err := hw.request(
		"PUT",
		fmt.Sprintf(huaweicloudEndpoint+"/v2.1/zones/%s/recordsets/%s", zoneID, recordsetID),
		&request,
		&result,
	)

	if err != nil {
		return fmt.Errorf("更新域名解析失败: %w", err)
	}

	if len(result.Records) == len(records) {
		util.Log("更新域名解析 %s 成功! IPs: %v", domain, result.Records)
		return nil
	}

	return fmt.Errorf("更新结果异常: %s", result.Status)
}

// 获得域名记录列表
func (hw *Huaweicloud) getZones(domain *config.Domain) (result HuaweicloudZonesResp, err error) {
	err = hw.request(
		"GET",
		huaweicloudEndpoint+"/v2/zones",
		url.Values{"name": []string{domain.DomainName}},
		&result,
	)

	return
}

// request 统一请求接口
func (hw *Huaweicloud) request(method string, urlString string, data interface{}, result interface{}) (err error) {
	var (
		req *http.Request
	)

	if method == "GET" {
		req, err = http.NewRequest(
			method,
			urlString,
			bytes.NewBuffer(nil),
		)

		req.URL.RawQuery = data.(url.Values).Encode()
	} else {
		jsonStr := make([]byte, 0)
		if data != nil {
			jsonStr, _ = json.Marshal(data)
		}

		req, err = http.NewRequest(
			method,
			urlString,
			bytes.NewBuffer(jsonStr),
		)
	}

	if err != nil {
		return
	}

	s := util.Signer{
		Key:    hw.DNS.ID,
		Secret: hw.DNS.Secret,
	}
	s.Sign(req)

	req.Header.Add("content-type", "application/json")

	client := hw.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}

// DeleteDomainRecord 删除单条记录（华为云不支持单个IP删除，因为使用recordset）
func (hw *Huaweicloud) DeleteDomainRecord(recordID string) error {
	// 华为云使用recordset管理，无法删除单个IP
	// 如需删除特定IP，应该更新整个recordset
	return fmt.Errorf("DeleteDomainRecord not implemented for Huaweicloud - use recordset updates instead")
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录
func (hw *Huaweicloud) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	return fmt.Errorf("DeleteAllDomainRecords not implemented for Huaweicloud")
}
