package dns

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// Eranet DNS实现
type Eranet struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}

type EranetRecord struct {
	ID     int `json:"id"`
	Domain string
	Host   string
	Type   string
	Value  string
	State  int
	// Name    string
	// Enabled string
}

type EranetRecordListResp struct {
	EranetBaseResult
	Data []EranetRecord
}

type EranetBaseResult struct {
	RequestId string `json:"RequestId"`
	Id        int    `json:"Id"`
	Error     string `json:"error"`
}

// Init 初始化
func (eranet *Eranet) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	eranet.DNS = dnsConf.DNS
	eranet.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认600s
		eranet.TTL = "600"
	} else {
		eranet.TTL = dnsConf.TTL
	}
	eranet.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (eranet *Eranet) AddUpdateDomainRecords() config.Domains {
	eranet.addUpdateDomainRecords("A")
	eranet.addUpdateDomainRecords("AAAA")
	return eranet.Domains
}

func (eranet *Eranet) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = eranet.Domains.Ipv4Addrs
		domains = eranet.Domains.Ipv4Domains
	} else {
		ipAddrs = eranet.Domains.Ipv6Addrs
		domains = eranet.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		result, err := eranet.getRecordList(domain, recordType)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range result.Data {
			currentIPs[record.Value] = strconv.Itoa(record.ID)
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
			eranet.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := eranet.DeleteDomainRecord(recordID); err != nil {
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

// create 创建DNS记录
func (eranet *Eranet) create(domain *config.Domain, recordType string, ipAddr string) {
	param := map[string]string{
		"Domain": domain.DomainName,
		"Host":   domain.GetSubDomain(),
		"Type":   recordType,
		"Value":  ipAddr,
		"Ttl":    eranet.TTL,
	}
	res, err := eranet.request("/api/Dns/AddDomainRecord", param, "GET")
	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err.Error())
		domain.UpdateStatus = config.UpdatedFailed
	}
	var result NowcnBaseResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err.Error())
		domain.UpdateStatus = config.UpdatedFailed
	}
	if result.Error != "" {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, result.Error)
		domain.UpdateStatus = config.UpdatedFailed
	} else {
		domain.UpdateStatus = config.UpdatedSuccess
	}
}

// DeleteDomainRecord 删除DNS记录
func (eranet *Eranet) DeleteDomainRecord(recordID string) error {
	param := map[string]string{
		"Id": recordID,
	}
	res, err := eranet.request("/api/Dns/DeleteDomainRecord", param, "GET")
	if err != nil {
		util.Log("删除域名记录 %s 失败! 异常信息: %s", recordID, err.Error())
		return err
	}
	var result EranetBaseResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		util.Log("删除域名记录 %s 失败! 异常信息: %s", recordID, err.Error())
		return err
	}
	if result.Error != "" {
		util.Log("删除域名记录 %s 失败! 异常信息: %s", recordID, result.Error)
		return fmt.Errorf(result.Error)
	}
	util.Log("删除域名记录 %s 成功!", recordID)
	return nil
}

// getRecordList 获取域名记录列表
func (eranet *Eranet) getRecordList(domain *config.Domain, typ string) (result EranetRecordListResp, err error) {
	param := map[string]string{
		"Domain": domain.DomainName,
		"Type":   typ,
		"Host":   domain.GetSubDomain(),
	}
	res, err := eranet.request("/api/Dns/DescribeRecordIndex", param, "GET")
	err = json.Unmarshal(res, &result)
	return
}

func (eranet *Eranet) queryParams(param map[string]any) string {
	var queryParams []string
	for key, value := range param {
		// 只对键进行URL编码，值保持原样（特别是@符号）
		encodedKey := url.QueryEscape(key)
		valueStr := fmt.Sprintf("%v", value)
		// 对值进行选择性编码，保留@符号
		encodedValue := strings.ReplaceAll(url.QueryEscape(valueStr), "%40", "@")
		encodedValue = strings.ReplaceAll(encodedValue, "%3A", ":")
		queryParams = append(queryParams, encodedKey+"="+encodedValue)
	}
	return strings.Join(queryParams, "&")
}

func (t *Eranet) sign(params map[string]string, method string) (string, error) {
	// 添加公共参数
	params["AccessInstanceID"] = t.DNS.ID
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureNonce"] = fmt.Sprintf("%d", time.Now().UnixNano())
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")

	// 1. 排序参数(按首字母顺序)
	var keys []string
	for k := range params {
		if k != "Signature" { // 排除Signature参数
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 2. 构造规范化请求字符串
	var canonicalizedQuery []string
	for _, k := range keys {
		// URL编码参数名和参数值
		encodedKey := util.PercentEncode(k)
		encodedValue := util.PercentEncode(params[k])
		canonicalizedQuery = append(canonicalizedQuery, encodedKey+"="+encodedValue)
	}
	canonicalizedQueryString := strings.Join(canonicalizedQuery, "&")

	// 3. 构造待签名字符串
	stringToSign := method + "&" + util.PercentEncode("/") + "&" + util.PercentEncode(canonicalizedQueryString)

	// 4. 计算HMAC-SHA1签名
	key := t.DNS.Secret + "&"
	h := hmac.New(sha1.New, []byte(key))
	h.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// 5. 添加签名到参数中
	params["Signature"] = signature

	// 6. 重新构造最终的查询字符串(包含签名)
	keys = append(keys, "Signature")
	sort.Strings(keys)
	var finalQuery []string
	for _, k := range keys {
		encodedKey := util.PercentEncode(k)
		encodedValue := util.PercentEncode(params[k])
		finalQuery = append(finalQuery, encodedKey+"="+encodedValue)
	}

	return strings.Join(finalQuery, "&"), nil
}

func (t *Eranet) request(apiPath string, params map[string]string, method string) ([]byte, error) {
	// 生成签名
	queryString, err := t.sign(params, method)
	if err != nil {
		return nil, fmt.Errorf("生成签名失败: %v", err)
	}

	// 构造完整URL
	baseURL := "https://www.eranet.com"
	fullURL := baseURL + apiPath + "?" + queryString

	// 创建HTTP请求
	req, err := http.NewRequest(method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Accept", "application/json")

	// 发送请求
	client := t.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查HTTP状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录
func (eranet *Eranet) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	result, err := eranet.getRecordList(domain, recordType)
	if err != nil {
		return fmt.Errorf("查询域名信息发生异常: %w", err)
	}

	for _, record := range result.Data {
		if err := eranet.DeleteDomainRecord(strconv.Itoa(record.ID)); err != nil {
			util.Log("删除记录 %s 失败: %s", record.Value, err.Error())
		}
	}

	return nil
}
