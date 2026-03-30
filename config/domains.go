package config

import (
	"net/url"
	"strings"

	"github.com/jeessy2/ddns-go/v6/util"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Domains Ipv4/Ipv6 domains
type Domains struct {
	Ipv4Addrs   []string
	Ipv4Domains []*Domain
	Ipv6Addrs   []string
	Ipv6Domains []*Domain
}

// Domain 域名实体
type Domain struct {
	// DomainName 根域名
	DomainName string
	// SubDomain 子域名
	SubDomain    string
	CustomParams string
	UpdateStatus updateStatusType // 更新状态
}

// nontransitionalLookup implements the nontransitional processing as specified in
// Unicode Technical Standard 46 with almost all checkings off to maximize user freedom.
//
// Copied from: https://github.com/cloudflare/cloudflare-go/blob/v0.97.0/dns.go#L95
var nontransitionalLookup = idna.New(
	idna.MapForLookup(),
	idna.StrictDomainName(false),
	idna.ValidateLabels(false),
)

func (d Domain) String() string {
	if d.SubDomain != "" {
		return d.SubDomain + "." + d.DomainName
	}
	return d.DomainName
}

// GetFullDomain 获得全部的，子域名
func (d Domain) GetFullDomain() string {
	if d.SubDomain != "" {
		return d.SubDomain + "." + d.DomainName
	}
	return "@" + "." + d.DomainName
}

// GetSubDomain 获得子域名，为空返回@
// 阿里云/腾讯云/dnspod/GoDaddy/namecheap 需要
func (d Domain) GetSubDomain() string {
	if d.SubDomain != "" {
		return d.SubDomain
	}
	return "@"
}

// GetCustomParams not be nil
func (d Domain) GetCustomParams() url.Values {
	if d.CustomParams != "" {
		q, err := url.ParseQuery(d.CustomParams)
		if err == nil {
			return q
		}
	}
	return url.Values{}
}

// ToASCII converts [Domain] to its ASCII form,
// using non-transitional process specified in UTS 46.
//
// Note: conversion errors are silently discarded and partial conversion
// results are used.
func (d Domain) ToASCII() string {
	name, _ := nontransitionalLookup.ToASCII(d.String())
	return name
}

// InitFromConfig 从配置初始化域名和IP
func (domains *Domains) InitFromConfig(dnsConf *DnsConfig) {
	domains.Ipv4Domains = checkParseDomains(dnsConf.Ipv4.Domains)
	domains.Ipv6Domains = checkParseDomains(dnsConf.Ipv6.Domains)

	if dnsConf.Ipv4.Enable && len(domains.Ipv4Domains) > 0 {
		domains.Ipv4Addrs = dnsConf.GetIpv4Addrs()
		if len(domains.Ipv4Addrs) == 0 {
			util.Log("未能获取IPv4地址, 将不会更新")
			domains.Ipv4Domains[0].UpdateStatus = UpdatedFailed
		}
	}

	if dnsConf.Ipv6.Enable && len(domains.Ipv6Domains) > 0 {
		domains.Ipv6Addrs = dnsConf.GetIpv6Addrs()
		if len(domains.Ipv6Addrs) == 0 {
			util.Log("未能获取IPv6地址, 将不会更新")
			domains.Ipv6Domains[0].UpdateStatus = UpdatedFailed
		}
	}
}

// checkParseDomains 校验并解析用户输入的域名
func checkParseDomains(domainArr []string) (domains []*Domain) {
	for _, domainStr := range domainArr {
		domainStr = strings.TrimSpace(domainStr)
		if domainStr == "" {
			continue
		}

		domain := &Domain{}

		// qp(queryParts) 从域名中提取自定义参数，如 baidu.com?q=1 => [baidu.com, q=1]
		qp := strings.Split(domainStr, "?")
		domainStr = qp[0]

		// dp(domainParts) 将域名（qp[0]）分割为子域名与根域名，如 www:example.cn.eu.org => [www, example.cn.eu.org]
		dp := strings.Split(domainStr, ":")

		switch len(dp) {
		case 1: // 不使用冒号分割，自动识别域名
			domainName, err := publicsuffix.EffectiveTLDPlusOne(domainStr)
			if err != nil {
				util.Log("域名: %s 不正确", domainStr)
				util.Log("异常信息: %s", err)
				continue
			}
			domain.DomainName = domainName

			domainLen := len(domainStr) - len(domainName) - 1
			if domainLen > 0 {
				domain.SubDomain = domainStr[:domainLen]
			}
		case 2: // 使用冒号分隔，为 子域名:根域名 格式
			sp := strings.Split(dp[1], ".")
			if len(sp) <= 1 {
				util.Log("域名: %s 不正确", domainStr)
				continue
			}
			domain.DomainName = dp[1]
			domain.SubDomain = dp[0]
		default:
			util.Log("域名: %s 不正确", domainStr)
			continue
		}

		// 参数条件
		if len(qp) == 2 {
			u, err := url.Parse("https://baidu.com?" + qp[1])
			if err != nil {
				util.Log("域名: %s 解析失败", domainStr)
				continue
			}
			domain.CustomParams = u.Query().Encode()
		}
		domains = append(domains, domain)
	}
	return
}
