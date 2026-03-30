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

const (
	rainyunEndpoint = "https://api.v2.rainyun.com"
)

// https://s.apifox.cn/a4595cc8-44c5-4678-a2a3-eed7738dab03/api-153559362
// Rainyun Rainyun
type Rainyun struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// RainyunRecord 雨云DNS记录
type RainyunRecord struct {
	RecordID int64  `json:"record_id"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Value    string `json:"value"`
	Line     string `json:"line"`
	TTL      int    `json:"ttl"`
	Level    int    `json:"level"`
}

// RainyunResp 雨云API通用响应
type RainyunResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data"`
}

// Init 初始化
func (rainyun *Rainyun) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	rainyun.DNS = dnsConf.DNS
	rainyun.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认600s
		rainyun.TTL = 600
	} else {
		ttlInt, _ := strconv.Atoi(dnsConf.TTL)
		rainyun.TTL = ttlInt
	}
	rainyun.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (rainyun *Rainyun) AddUpdateDomainRecords() (domains config.Domains) {
	rainyun.addUpdateDomainRecords("A")
	rainyun.addUpdateDomainRecords("AAAA")
	return rainyun.Domains
}

func (rainyun *Rainyun) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = rainyun.Domains.Ipv4Addrs
		domains = rainyun.Domains.Ipv4Domains
	} else {
		ipAddrs = rainyun.Domains.Ipv6Addrs
		domains = rainyun.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 获取Domain ID
		domainID := rainyun.DNS.ID

		// 步骤1：获取当前所有记录
		records, err := rainyun.getRecordList(domainID)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range records {
			if strings.EqualFold(record.Host, domain.GetSubDomain()) &&
				strings.EqualFold(record.Type, recordType) {
				// 使用 RecordID 转换为字符串作为记录标识
				currentIPs[record.Value] = strconv.FormatInt(record.RecordID, 10)
				util.Log("current value: %s", record.Value)
			}
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

		createdCount := 0
		for _, ip := range compareResult.ToCreate {
			rainyun.create(domainID, domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := rainyun.DeleteDomainRecord(domainID, recordID); err != nil {
				util.Log("删除记录失败，继续处理: %s", err)
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

// getRecordList 获取域名记录列表
func (rainyun *Rainyun) getRecordList(domainID string) ([]RainyunRecord, error) {
	query := url.Values{}
	query.Set("limit", "100")
	query.Set("page_no", "1")

	var result struct {
		TotalRecords int             `json:"TotalRecords"`
		Records      []RainyunRecord `json:"Records"`
	}
	err := rainyun.request(
		http.MethodGet,
		fmt.Sprintf("/product/domain/%s/dns/", url.PathEscape(domainID)),
		query,
		nil,
		&result,
	)
	if err != nil {
		return nil, err
	}
	return result.Records, nil
}

// create 创建DNS记录
func (rainyun *Rainyun) create(domainID string, domain *config.Domain, recordType string, ipAddr string) {
	record := &RainyunRecord{
		Host:  domain.GetSubDomain(),
		Type:  recordType,
		Value: ipAddr,
		Line:  "DEFAULT",
		TTL:   rainyun.TTL,
		Level: 10,
	}

	err := rainyun.createRecord(domainID, record)
	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
		return
	}

	util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
	domain.UpdateStatus = config.UpdatedSuccess
}

// createRecord 发送POST请求创建记录
func (rainyun *Rainyun) createRecord(domainID string, record *RainyunRecord) error {
	payload := map[string]any{
		"host":      record.Host,
		"line":      record.Line,
		"level":     record.Level,
		"ttl":       record.TTL,
		"type":      record.Type,
		"value":     record.Value,
		"record_id": 0,
	}

	byt, _ := json.Marshal(payload)
	return rainyun.request(
		http.MethodPost,
		fmt.Sprintf("/product/domain/%s/dns", url.PathEscape(domainID)),
		nil,
		byt,
		nil,
	)
}

// DeleteDomainRecord 删除DNS记录
func (rainyun *Rainyun) DeleteDomainRecord(domainID string, recordID string) error {
	// 将字符串 recordID 转换为 int64
	recordIDInt, err := strconv.ParseInt(recordID, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid record ID: %s", recordID)
	}

	query := url.Values{}
	query.Set("record_id", strconv.FormatInt(recordIDInt, 10))

	err = rainyun.request(
		http.MethodDelete,
		fmt.Sprintf("/product/domain/%s/dns", url.PathEscape(domainID)),
		query,
		nil,
		nil,
	)
	if err != nil {
		return fmt.Errorf("删除记录失败: %s", err)
	}

	util.Log("删除记录成功! RecordID: %s", recordID)
	return nil
}

// patchRecord 发送PATCH请求更新记录
func (rainyun *Rainyun) patchRecord(domainID string, record *RainyunRecord) error {
	payload := map[string]any{
		"host":      record.Host,
		"line":      record.Line,
		"level":     record.Level,
		"ttl":       record.TTL,
		"type":      record.Type,
		"value":     record.Value,
		"record_id": record.RecordID,
	}

	byt, _ := json.Marshal(payload)
	return rainyun.request(
		http.MethodPatch,
		fmt.Sprintf("/product/domain/%s/dns", url.PathEscape(domainID)),
		nil,
		byt,
		nil,
	)
}

// request 统一请求接口
func (rainyun *Rainyun) request(method string, path string, query url.Values, body []byte, result any) error {
	u, err := url.Parse(rainyunEndpoint)
	if err != nil {
		return err
	}
	u.Path = path
	if query != nil {
		u.RawQuery = query.Encode()
	}

	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, u.String(), reader)
	if err != nil {
		return err
	}
	// 认证
	req.Header.Set("x-api-key", rainyun.DNS.Secret)
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := rainyun.httpClient.Do(req)
	if err != nil {
		return err
	}

	var apiResp RainyunResp
	err = util.GetHTTPResponse(resp, err, &apiResp)
	if err != nil {
		return err
	}
	if apiResp.Code != 200 {
		if apiResp.Message != "" {
			return fmt.Errorf("%s", apiResp.Message)
		}
		return fmt.Errorf("Rainyun API error, code=%d", apiResp.Code)
	}

	if result == nil {
		return nil
	}

	dataBytes, err := json.Marshal(apiResp.Data)
	if err != nil {
		return err
	}
	return json.Unmarshal(dataBytes, result)
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录
func (rainyun *Rainyun) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	domainID := rainyun.DNS.ID

	// 获取当前所有记录
	records, err := rainyun.getRecordList(domainID)
	if err != nil {
		return fmt.Errorf("查询域名记录失败: %s", err)
	}

	// 删除所有匹配的记录
	for _, record := range records {
		if strings.EqualFold(record.Host, domain.GetSubDomain()) &&
			strings.EqualFold(record.Type, recordType) {
			recordID := strconv.FormatInt(record.RecordID, 10)
			if err := rainyun.DeleteDomainRecord(domainID, recordID); err != nil {
				util.Log("删除记录失败: %s", err)
			}
		}
	}

	return nil
}
