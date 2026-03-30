package dns

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// TrafficRoute 火山引擎DNS服务
type TrafficRoute struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// TrafficRouteMeta 解析记录
type TrafficRouteMeta struct {
	ZID      int    `json:"ZID"`      // 域名ID
	RecordID string `json:"RecordID"` // 解析记录ID
	Host     string `json:"Host"`     // 主机记录
	Type     string `json:"Type"`     // 记录类型
	Value    string `json:"Value"`    // 记录值
	TTL      int    `json:"TTL"`      // TTL值
	Line     string `json:"Line"`     // 解析线路
}

// TrafficRouteResp API响应通用结构
type TrafficRouteResp struct {
	ResponseMetadata struct {
		RequestId string `json:"RequestId"`
		Action    string `json:"Action"`
		Version   string `json:"Version"`
		Service   string `json:"Service"`
		Region    string `json:"Region"`
		Error     struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
	} `json:"ResponseMetadata"`
	Result struct {
		// 域名列表相关字段
		Zones []struct {
			ZID         int    `json:"ZID"`
			ZoneName    string `json:"ZoneName"`
			RecordCount int    `json:"RecordCount"`
		} `json:"Zones,omitempty"`
		Total int `json:"Total,omitempty"`

		// 解析记录相关字段
		Records    []TrafficRouteMeta `json:"Records,omitempty"`
		TotalCount int                `json:"TotalCount,omitempty"`

		// 创建/更新记录相关字段
		RecordID string `json:"RecordID,omitempty"`
		Status   bool   `json:"Status,omitempty"`
	} `json:"Result"`
}

// TrafficRouteListZonesParams ListZones查询参数
type TrafficRouteListZonesParams struct {
	Key string `json:"Key,omitempty"` // 获取包含特定关键字的域名(默认模糊搜索)
}

// TrafficRouteListZonesResp
type TrafficRouteListZonesResp struct {
	ZID int `json:"ZID"` // 域名ID
}

func (tr *TrafficRoute) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	tr.DNS = dnsConf.DNS
	tr.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		tr.TTL = 600
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			tr.TTL = 600
		} else {
			tr.TTL = ttl
		}
	}
	tr.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (tr *TrafficRoute) AddUpdateDomainRecords() config.Domains {
	tr.addUpdateDomainRecords("A")
	tr.addUpdateDomainRecords("AAAA")
	return tr.Domains
}

func (tr *TrafficRoute) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = tr.Domains.Ipv4Addrs
		domains = tr.Domains.Ipv4Domains
	} else {
		ipAddrs = tr.Domains.Ipv6Addrs
		domains = tr.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取zone ID
		resp := TrafficRouteListZonesResp{}
		tr.getZID(domain, &resp)
		if domain.UpdateStatus == config.UpdatedFailed {
			continue
		}
		zoneID := resp.ZID

		// 步骤2：获取现有记录
		var recordResp TrafficRouteResp
		tr.request(
			"GET",
			"ListRecords",
			map[string][]string{
				"ZID":        {strconv.Itoa(zoneID)},
				"Type":       {recordType},
				"Host":       {domain.GetSubDomain()},
				"SearchMode": {"exact"},
				"PageNumber": {"1"},
				"PageSize":   {"500"},
			},
			&recordResp,
		)

		// 步骤3：构建当前IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range recordResp.Result.Records {
			if record.Type == recordType && record.Host == domain.GetSubDomain() {
				currentIPs[record.Value] = record.RecordID
				util.Log("current value: %s", record.Value)
			}
		}

		// 步骤4：使用工具函数比较DNS记录
		compareResult := util.CompareDNSRecords(currentIPs, ipAddrs)

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

		// 步骤5：创建新记录
		createdCount := 0
		for _, ip := range compareResult.ToCreate {
			tr.create(zoneID, domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		// 步骤6：删除多余记录 (注意：TrafficRoute可能不支持删除，需要检查)
		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			// TrafficRoute delete not implemented yet, skip for now
			util.Log("TrafficRoute暂不支持删除记录，跳过删除 RecordID: %s", recordID)
		}

		// 步骤7：计算保持不变的记录数
		unchangedCount := 0
		for ip := range compareResult.DesiredIPs {
			if _, exists := currentIPs[ip]; exists {
				unchangedCount++
			}
		}

		// 步骤8：统一的状态更新和日志
		if createdCount == len(compareResult.ToCreate) && len(compareResult.ToDelete) == deletedCount {
			util.Log("✓ 别名模式更新完成: %s | 保持: %d 个 | 新增: %d 个 | 删除: %d 个",
				domain, unchangedCount, createdCount, deletedCount)
			if createdCount > 0 || deletedCount > 0 {
				domain.UpdateStatus = config.UpdatedSuccess
			} else {
				domain.UpdateStatus = config.UpdatedFailed
			}
		}
	}
}

// getZID 获取域名的ZID
func (tr *TrafficRoute) getZID(domain *config.Domain, resp *TrafficRouteListZonesResp) {
	var result TrafficRouteResp
	err := tr.request(
		"GET",
		"ListZones",
		map[string][]string{"Key": {domain.DomainName}},
		&result,
	)

	if err != nil {
		util.Log("查询域名信息发生异常! %s", err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if len(result.Result.Zones) == 0 {
		util.Log("在DNS服务商中未找到域名: %s", domain.DomainName)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	for _, zone := range result.Result.Zones {
		if zone.ZoneName == domain.DomainName {
			resp.ZID = zone.ZID
			return
		}
	}
}

// create 添加解析记录
func (tr *TrafficRoute) create(zoneID int, domain *config.Domain, recordType, ipAddr string) {
	record := &TrafficRouteMeta{
		ZID:   zoneID,
		Host:  domain.GetSubDomain(),
		Type:  recordType,
		Value: ipAddr,
		TTL:   tr.TTL,
		Line:  "default",
	}

	var result TrafficRouteResp
	err := tr.request(
		"POST",
		"CreateRecord",
		record,
		&result,
	)

	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if result.ResponseMetadata.Error.Code == "" {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, result.ResponseMetadata.Error.Message)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// modify 修改解析记录
func (tr *TrafficRoute) modify(record TrafficRouteMeta, domain *config.Domain, ipAddr string) {
	if record.Value == ipAddr {
		util.Log("IP %s 没有变化，域名 %s", ipAddr, domain)
		domain.UpdateStatus = config.UpdatedNothing
		return
	}

	record.Value = ipAddr
	record.TTL = tr.TTL

	var result TrafficRouteResp
	err := tr.request(
		"POST",
		"UpdateRecord",
		record,
		&result,
	)

	if err != nil {
		util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	if result.ResponseMetadata.Error.Code == "" {
		util.Log("更新域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, result.ResponseMetadata.Error.Message)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// parseRequestParams 解析请求参数
func (tr *TrafficRoute) parseRequestParams(action string, data interface{}) (queryParams map[string][]string, jsonStr []byte, err error) {
	queryParams = make(map[string][]string)

	switch v := data.(type) {
	case map[string][]string:
		queryParams = v
		jsonStr = []byte{}
	case *TrafficRouteMeta:
		jsonStr, _ = json.Marshal(v)
	default:
		if data != nil {
			jsonStr, _ = json.Marshal(data)
		}
	}

	// 根据不同action处理参数
	switch action {
	case "ListZones":
		if len(queryParams) == 0 && len(jsonStr) > 0 {
			var params TrafficRouteListZonesParams
			if err = json.Unmarshal(jsonStr, &params); err == nil && params.Key != "" {
				queryParams["Key"] = []string{params.Key}
			}
			jsonStr = []byte{}
		}
	case "ListRecords":
		if len(queryParams) == 0 && len(jsonStr) > 0 {
			var params TrafficRouteListZonesResp
			if err = json.Unmarshal(jsonStr, &params); err == nil && params.ZID != 0 {
				queryParams["ZID"] = []string{strconv.Itoa(params.ZID)}
			}
			jsonStr = []byte{}
		}
	}

	return
}

// request 统一请求接口
func (tr *TrafficRoute) request(method string, action string, data interface{}, result interface{}) error {
	queryParams, jsonStr, err := tr.parseRequestParams(action, data)
	if err != nil {
		return err
	}

	req, err := util.TrafficRouteSigner(method, queryParams, map[string]string{}, tr.DNS.ID, tr.DNS.Secret, action, jsonStr)
	if err != nil {
		return err
	}

	client := tr.httpClient
	resp, err := client.Do(req)
	return util.GetHTTPResponse(resp, err, result)
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (tra *TrafficRoute) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("TrafficRoute provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for TrafficRoute provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
