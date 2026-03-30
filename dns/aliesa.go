package dns

import (
	"net/http"
	"net/url"

	"github.com/jeessy2/ddns-go/v6/config"
	"github.com/jeessy2/ddns-go/v6/util"
)

const aliesaEndpoint = "https://esa.cn-hangzhou.aliyuncs.com/"

type Aliesa struct {
	DNS        config.DNS
	Domains    config.Domains
	TTL        string
	httpClient *http.Client
}

func (ali *Aliesa) Init(dnsConf *config.DnsConfig, _ *util.IpCache, _ *util.IpCache) {
	ali.DNS = dnsConf.DNS
	ali.Domains.InitFromConfig(dnsConf)
	if dnsConf.TTL == "" {
		ali.TTL = "600"
	} else {
		ali.TTL = dnsConf.TTL
	}
	ali.httpClient = dnsConf.GetHTTPClient()
}

func (ali *Aliesa) AddUpdateDomainRecords() config.Domains {
	for _, domain := range ali.Domains.Ipv4Domains {
		util.Log("Aliesa: 别名模式暂不支持，请使用 alidns 提供商")
		domain.UpdateStatus = config.UpdatedFailed
	}
	for _, domain := range ali.Domains.Ipv6Domains {
		util.Log("Aliesa: 别名模式暂不支持，请使用 alidns 提供商")
		domain.UpdateStatus = config.UpdatedFailed
	}
	return ali.Domains
}

func (ali *Aliesa) request(method string, params url.Values, result interface{}) error {
	util.AliyunSigner(ali.DNS.ID, ali.DNS.Secret, &params, method, "2024-09-10")
	req, _ := http.NewRequest(method, aliesaEndpoint, nil)
	req.URL.RawQuery = params.Encode()
	resp, err := ali.httpClient.Do(req)
	return util.GetHTTPResponse(resp, err, result)
}

func (ali *Aliesa) DeleteAllDomainRecords(domain *config.Domain, recordType string) error {
	panic("Aliesa provider does not support alias mode. Use 'alidns' provider instead.")
}
