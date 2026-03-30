package dns

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

// https://cloud.baidu.com/doc/BCD/s/4jwvymhs7

const (
	baiduEndpoint = "https://bcd.baidubce.com"
)

type BaiduCloud struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        int
	httpClient *http.Client
}

// BaiduRecord 单条解析记录
type BaiduRecord struct {
	RecordId uint   `json:"recordId"`
	Domain   string `json:"domain"`
	View     string `json:"view"`
	Rdtype   string `json:"rdtype"`
	TTL      int    `json:"ttl"`
	Rdata    string `json:"rdata"`
	ZoneName string `json:"zoneName"`
	Status   string `json:"status"`
}

// BaiduRecordsResp 获取解析列表拿到的结果
type BaiduRecordsResp struct {
	TotalCount int           `json:"totalCount"`
	Result     []BaiduRecord `json:"result"`
}

// BaiduListRequest 获取解析列表请求的body json
type BaiduListRequest struct {
	Domain   string `json:"domain"`
	PageNum  int    `json:"pageNum"`
	PageSize int    `json:"pageSize"`
}

// BaiduModifyRequest 修改解析请求的body json
type BaiduModifyRequest struct {
	RecordId uint   `json:"recordId"`
	Domain   string `json:"domain"`
	View     string `json:"view"`
	RdType   string `json:"rdType"`
	TTL      int    `json:"ttl"`
	Rdata    string `json:"rdata"`
	ZoneName string `json:"zoneName"`
}

// BaiduCreateRequest 创建新解析请求的body json
type BaiduCreateRequest struct {
	Domain   string `json:"domain"`
	RdType   string `json:"rdType"`
	TTL      int    `json:"ttl"`
	Rdata    string `json:"rdata"`
	ZoneName string `json:"zoneName"`
}

func (baidu *BaiduCloud) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	baidu.DNS = dnsConf.DNS
	baidu.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		baidu.TTL = 300
	} else {
		ttl, err := strconv.Atoi(dnsConf.TTL)
		if err != nil {
			baidu.TTL = 300
		} else {
			baidu.TTL = ttl
		}
	}
	baidu.httpClient = dnsConf.GetHTTPClient()
}

func (baidu *BaiduCloud) AddUpdateDomainRecords() config.Domains {
	baidu.addUpdateDomainRecords("A")
	baidu.addUpdateDomainRecords("AAAA")
	return baidu.Domains
}

func (baidu *BaiduCloud) addUpdateDomainRecords(recordType string) {
	// 获取IP地址列表
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = baidu.Domains.Ipv4Addrs
		domains = baidu.Domains.Ipv4Domains
	} else {
		ipAddrs = baidu.Domains.Ipv6Addrs
		domains = baidu.Domains.Ipv6Domains
	}

	for _, domain := range domains {
		// 别名模式：智能更新 - 最小化变更，避免服务中断
		util.Log("别名模式：智能更新域名 %s 的 %s 记录", domain, recordType)

		// 步骤1：获取当前所有记录
		var records BaiduRecordsResp
		requestBody := BaiduListRequest{
			Domain:   domain.DomainName,
			PageNum:  1,
			PageSize: 1000,
		}

		err := baidu.request("POST", baiduEndpoint+"/v1/domain/resolve/list", requestBody, &records)
		if err != nil {
			util.Log("查询域名信息发生异常! %s", err)
			domain.UpdateStatus = config.UpdatedFailed
			continue
		}

		// 步骤2：构建当前IP集合和期望IP集合
		currentIPs := make(map[string]string) // map[IP]RecordID
		for _, record := range records.Result {
			if record.Domain == domain.GetSubDomain() && record.Rdtype == recordType {
				currentIPs[record.Rdata] = strconv.FormatUint(uint64(record.RecordId), 10)
				util.Log("current value: %s", record.Rdata)
			}
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
			baidu.create(domain, recordType, ip)
			if domain.UpdateStatus == config.UpdatedSuccess {
				createdCount++
			}
		}

		deletedCount := 0
		for _, recordID := range compareResult.ToDelete {
			if err := baidu.DeleteDomainRecord(recordID); err != nil {
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

func (baidu *BaiduCloud) create(domain *config.Domain, recordType string, ipAddr string) {
	var baiduCreateRequest = BaiduCreateRequest{
		Domain:   domain.GetSubDomain(), //处理一下@
		RdType:   recordType,
		TTL:      baidu.TTL,
		Rdata:    ipAddr,
		ZoneName: domain.DomainName,
	}
	var result BaiduRecordsResp

	err := baidu.request("POST", baiduEndpoint+"/v1/domain/resolve/add", baiduCreateRequest, &result)
	if err == nil {
		util.Log("新增域名解析 %s 成功! IP: %s", domain, ipAddr)
		domain.UpdateStatus = config.UpdatedSuccess
	} else {
		util.Log("新增域名解析 %s 失败! 异常信息: %s", domain, err)
		domain.UpdateStatus = config.UpdatedFailed
	}
}

// DeleteDomainRecord 删除域名记录
func (baidu *BaiduCloud) DeleteDomainRecord(recordID string) error {
	recordIDUint, err := strconv.ParseUint(recordID, 10, 32)
	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 无效的记录ID: %s", recordID, err)
		return err
	}

	// 使用删除API端点 /v1/domain/resolve/delete
	type BaiduDeleteRequest struct {
		RecordId uint `json:"recordId"`
	}

	deleteRequest := BaiduDeleteRequest{
		RecordId: uint(recordIDUint),
	}

	var records BaiduRecordsResp
	err = baidu.request("POST", baiduEndpoint+"/v1/domain/resolve/delete", deleteRequest, &records)
	if err != nil {
		util.Log("删除域名记录失败! RecordId: %s, 异常信息: %s", recordID, err)
		return err
	}

	util.Log("删除域名记录成功! RecordId: %s", recordID)
	return nil
}

// request 统一请求接口
func (baidu *BaiduCloud) request(method string, url string, data interface{}, result interface{}) (err error) {
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

	util.BaiduSigner(baidu.DNS.ID, baidu.DNS.Secret, req)

	client := baidu.httpClient
	resp, err := client.Do(req)
	err = util.GetHTTPResponse(resp, err, result)

	return
}
