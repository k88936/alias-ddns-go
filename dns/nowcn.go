package dns

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// https://www.todaynic.com/docApi/
// Nowcn nowcn DNS实现
type Nowcn struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}

// NowcnRecord DNS记录结构
type NowcnRecord struct {
	ID     int `json:"id"`
	Domain string
	Host   string
	Type   string
	Value  string
	State  int
	// Name    string
	// Enabled string
}

// NowcnRecordListResp 记录列表响应
type NowcnRecordListResp struct {
	NowcnBaseResult
	Data []NowcnRecord
}

// NowcnStatus API响应状态
type NowcnBaseResult struct {
	RequestId string `json:"RequestId"`
	Id        int    `json:"Id"`
	Error     string `json:"error"`
}

// Init 初始化
func (nowcn *Nowcn) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	nowcn.DNS = dnsConf.DNS
	nowcn.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		// 默认600s
		nowcn.TTL = "600"
	} else {
		nowcn.TTL = dnsConf.TTL
	}
	nowcn.httpClient = dnsConf.GetHTTPClient()
}

// AddUpdateDomainRecords 添加或更新IPv4/IPv6记录
func (nowcn *Nowcn) AddUpdateDomainRecords() config.Domains {
	nowcn.addUpdateDomainRecords("A")
	nowcn.addUpdateDomainRecords("AAAA")
	return nowcn.Domains
}

func (nowcn *Nowcn) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = nowcn.Domains.Ipv4Addrs
		domains = nowcn.Domains.Ipv4Domains
	} else {
		ipAddrs = nowcn.Domains.Ipv6Addrs
		domains = nowcn.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取现有记录
		result, err := nowcn.getRecordList(domain, recordType)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range result.Data {
			currentIPs[record.Value] = strconv.Itoa(record.ID)
			util.Log("current value: %s", record.Value)
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
			nowcn.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		// 步骤5：删除多余记录
		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := nowcn.DeleteDomainRecord(recordID); err != nil {
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

		// 步骤7：统一的状态更新和日志
		if createdCount == len(compareResult.ToCreate) && deletedCount == len(compareResult.ToDelete) {
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

// create 创建DNS记录
func (nowcn *Nowcn) create(domain *config.Domain, recordType string, ipAddr string) {
	param := map[string]string{
		"Domain": domain.DomainName,
		"Host":   domain.GetSubDomain(),
		"Type":   recordType,
		"Value":  ipAddr,
		"Ttl":    nowcn.TTL,
	}
	res, err := nowcn.request("/api/Dns/AddDomainRecord", param, "GET")
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

// modify 修改DNS记录
func (nowcn *Nowcn) modify(record NowcnRecord, domain *config.Domain, recordType string, ipAddr string) {
	// 相同不修改
	if record.Value == ipAddr {
		util.Log("你的IP %s 没有变化, 域名 %s", ipAddr, domain)
		return
	}
	param := map[string]string{
		"Id":     strconv.Itoa(record.ID),
		"Domain": domain.DomainName,
		"Host":   domain.GetSubDomain(),
		"Type":   recordType,
		"Value":  ipAddr,
		"Ttl":    nowcn.TTL,
	}
	res, err := nowcn.request("/api/Dns/UpdateDomainRecord", param, "GET")
	if err != nil {
		util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, err.Error())
		domain.UpdateStatus = config.UpdatedFailed
	}
	var result NowcnBaseResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, err.Error())
		domain.UpdateStatus = config.UpdatedFailed
	}
	if result.Error != "" {
		util.Log("更新域名解析 %s 失败! 异常信息: %s", domain, result.Error)
		domain.UpdateStatus = config.UpdatedFailed
	} else {
		util.Log("更新域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	}
}

// DeleteDomainRecord 删除DNS记录
func (nowcn *Nowcn) DeleteDomainRecord(recordID string) error {
	param := map[string]string{
		"Id": recordID,
	}
	res, err := nowcn.request("/api/Dns/RemoveDomainRecord", param, "GET")
	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}
	var result NowcnBaseResult
	err = json.Unmarshal(res, &result)
	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}
	if result.Error != "" {
		err = fmt.Errorf("%s", result.Error)
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}
	util.Log("成功删除记录ID: %s", recordID)
	return nil
}

// getRecordList 获取域名记录列表
func (nowcn *Nowcn) getRecordList(domain *config.Domain, typ string) (result NowcnRecordListResp, err error) {
	param := map[string]string{
		"Domain": domain.DomainName,
		"Type":   typ,
		"Host":   domain.GetSubDomain(),
	}
	res, err := nowcn.request("/api/Dns/DescribeRecordIndex", param, "GET")
	err = json.Unmarshal(res, &result)
	return
}

func (t *Nowcn) sign(params map[string]string, method string) (string, error) {
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

func (t *Nowcn) request(apiPath string, params map[string]string, method string) ([]byte, error) {
	// 生成签名
	queryString, err := t.sign(params, method)
	if err != nil {
		return nil, fmt.Errorf("生成签名失败: %v", err)
	}

	// 构造完整URL
	baseURL := "https://api.now.cn"
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

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (now *Nowcn) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Nowcn provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for Nowcn provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
