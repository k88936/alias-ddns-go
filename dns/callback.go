package dns

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

type Callback struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	lastIpv4   string
	lastIpv6   string
	httpClient *http.Client
}

func (cb *Callback) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	cb.DNS = dnsConf.DNS
	cb.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		cb.TTL = "600"
	} else {
		cb.TTL = dnsConf.TTL
	}
	cb.httpClient = dnsConf.GetHTTPClient()
}

func (cb *Callback) AddUpdateDomainRecords() config.Domains {
	cb.addUpdateDomainRecords("A")
	cb.addUpdateDomainRecords("AAAA")
	return cb.Domains
}

func (cb *Callback) addUpdateDomainRecords(recordType string) {
	var ipAddrs []string
	var domains []*config.Domain
	if recordType == "A" {
		ipAddrs = cb.Domains.Ipv4Addrs
		domains = cb.Domains.Ipv4Domains
	} else {
		ipAddrs = cb.Domains.Ipv6Addrs
		domains = cb.Domains.Ipv6Domains
	}

	if len(ipAddrs) == 0 {
		return
	}

	for _, domain := range domains {
		for _, ipAddr := range ipAddrs {
			method := "GET"
			postPara := ""
			contentType := "application/x-www-form-urlencoded"
			if cb.DNS.Secret != "" {
				method = "POST"
				postPara = replacePara(cb.DNS.Secret, ipAddr, domain, recordType, cb.TTL)
				if json.Valid([]byte(postPara)) {
					contentType = "application/json"
				}
			}
			requestURL := replacePara(cb.DNS.ID, ipAddr, domain, recordType, cb.TTL)
			u, err := url.Parse(requestURL)
			if err != nil {
				util.Log("Callback的URL不正确")
				return
			}
			req, err := http.NewRequest(method, u.String(), strings.NewReader(postPara))
			if err != nil {
				util.Log("异常信息: %s", err)
				domain.UpdateStatus = config.UpdatedFailed
				return
			}
			req.Header.Add("content-type", contentType)

			clt := util.CreateHTTPClient()
			resp, err := clt.Do(req)
			body, err := util.GetHTTPResponseOrg(resp, err)
			if err == nil {
				util.Log("Callback调用成功, 域名: %s, IP: %s, 返回数据: %s", domain, ipAddr, string(body))
				domain.UpdateStatus = config.UpdatedSuccess
			} else {
				util.Log("Callback调用失败, 异常信息: %s", err)
				domain.UpdateStatus = config.UpdatedFailed
			}
		}
	}
}

func replacePara(orgPara, ipAddr string, domain *config.Domain, recordType string, ttl string) string {
	// params 使用 map 以便添加更多参数
	params := map[string]string{
		"ip":         ipAddr,
		"domain":     domain.String(),
		"recordType": recordType,
		"ttl":        ttl,
	}

	// 也替换域名的自定义参数
	for k, v := range domain.GetCustomParams() {
		if len(v) == 1 {
			params[k] = v[0]
		}
	}

	// 将 map 转换为 [NewReplacer] 所需的参数
	// map 中的每个元素占用 2 个位置（kv），因此需要预留 2 倍的空间
	oldnew := make([]string, 0, len(params)*2)
	for k, v := range params {
		k = fmt.Sprintf("#{%s}", k)
		oldnew = append(oldnew, k, v)
	}

	return strings.NewReplacer(oldnew...).Replace(orgPara)
}

// DeleteAllDomainRecords 删除域名的所有指定类型记录（未实现）
func (cal *Callback) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Callback provider does not support delete operation yet for alias aggregation feature. " +
		"Please use Aliyun DNS provider (dns.name: 'alidns') for alias aggregation, " +
		"or implement the delete operation for Callback provider. " +
		"Refer to dns/alidns.go for implementation example.")
}
