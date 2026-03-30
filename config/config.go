package config

import (
	"errors"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"

	"github.com/jeessy2/ddns-go/v6/util"
	passwordvalidator "github.com/wagslane/go-password-validator"
	"gopkg.in/yaml.v3"
)

// Ipv4Reg IPv4正则
var Ipv4Reg = regexp.MustCompile(`((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])`)

// Ipv6Reg IPv6正则
var Ipv6Reg = regexp.MustCompile(`((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))`)

// DnsConfig 配置
type DnsConfig struct {
	Name string
	Ipv4 struct {
		Enable  bool
		Sources []string // 别名源域名列表，用于聚合多个域名的IP
		Domains []string
	}
	Ipv6 struct {
		Enable  bool
		Sources []string // 别名源域名列表，用于聚合多个域名的IP
		Domains []string
	}
	DNS DNS
	TTL string
	// 发送HTTP请求时使用的网卡名称，为空则使用默认网卡
	HttpInterface string
}

// DNS DNS配置
type DNS struct {
	// 名称。如：alidns,webhook
	Name   string
	ID     string
	Secret string
	// ExtParam 扩展参数，用于某些DNS提供商的特殊需求（如Vercel的teamId）
	ExtParam string
}

type Config struct {
	DnsConf []DnsConfig
	User
	Webhook
	// 禁止公网访问
	NotAllowWanAccess bool
	// 语言
	Lang string
}

// ConfigCache ConfigCache
type cacheType struct {
	ConfigSingle *Config
	Err          error
	Lock         sync.Mutex
}

var cache = &cacheType{}

// GetConfigCached 获得缓存的配置
func GetConfigCached() (conf Config, err error) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	if cache.ConfigSingle != nil {
		return *cache.ConfigSingle, cache.Err
	}

	// init config
	cache.ConfigSingle = &Config{}

	configFilePath := util.GetConfigFilePath()
	_, err = os.Stat(configFilePath)
	if err != nil {
		cache.Err = err
		return *cache.ConfigSingle, err
	}

	byt, err := os.ReadFile(configFilePath)
	if err != nil {
		util.Log("异常信息: %s", err)
		cache.Err = err
		return *cache.ConfigSingle, err
	}

	err = yaml.Unmarshal(byt, cache.ConfigSingle)
	if err != nil {
		util.Log("异常信息: %s", err)
		cache.Err = err
		return *cache.ConfigSingle, err
	}

	// 未填写登录信息, 确保不能从公网访问
	if cache.ConfigSingle.Username == "" && cache.ConfigSingle.Password == "" {
		cache.ConfigSingle.NotAllowWanAccess = true
	}

	// remove err
	cache.Err = nil
	return *cache.ConfigSingle, err
}

// CompatibleConfig 兼容之前的配置文件
func (conf *Config) CompatibleConfig() {

	// 如果之前密码不为空且不是bcrypt加密后的密码, 把密码加密并保存
	if conf.Password != "" && !util.IsHashedPassword(conf.Password) {
		hashedPwd, err := util.HashPassword(conf.Password)
		if err == nil {
			conf.Password = hashedPwd
			conf.SaveConfig()
		}
	}

	// 兼容v5.0.0之前的配置文件
	if len(conf.DnsConf) > 0 {
		return
	}

	configFilePath := util.GetConfigFilePath()
	_, err := os.Stat(configFilePath)
	if err != nil {
		return
	}
	byt, err := os.ReadFile(configFilePath)
	if err != nil {
		return
	}

	dnsConf := &DnsConfig{}
	err = yaml.Unmarshal(byt, dnsConf)
	if err != nil {
		return
	}
	if len(dnsConf.DNS.Name) > 0 {
		cache.Lock.Lock()
		defer cache.Lock.Unlock()
		conf.DnsConf = append(conf.DnsConf, *dnsConf)
		cache.ConfigSingle = conf
	}
}

// SaveConfig 保存配置
func (conf *Config) SaveConfig() (err error) {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	byt, err := yaml.Marshal(conf)
	if err != nil {
		log.Println(err)
		return err
	}

	configFilePath := util.GetConfigFilePath()
	err = os.WriteFile(configFilePath, byt, 0600)
	if err != nil {
		log.Println(err)
		return
	}

	util.Log("配置文件已保存在: %s", configFilePath)

	// 清空配置缓存
	cache.ConfigSingle = nil

	return
}

// 重置密码
func (conf *Config) ResetPassword(newPassword string) {
	// 初始化语言
	util.InitLogLang(conf.Lang)

	// 先检查密码是否安全
	hashedPwd, err := conf.CheckPassword(newPassword)
	if err != nil {
		util.Log(err.Error())
		return
	}

	// 保存配置
	conf.Password = hashedPwd
	conf.SaveConfig()
	util.Log("用户名 %s 的密码已重置成功! 请重启ddns-go", conf.Username)
}

// CheckPassword 检查密码
func (conf *Config) CheckPassword(newPassword string) (hashedPwd string, err error) {
	var minEntropyBits float64 = 30
	if conf.NotAllowWanAccess {
		minEntropyBits = 25
	}
	err = passwordvalidator.Validate(newPassword, minEntropyBits)
	if err != nil {
		return "", errors.New(util.LogStr("密码不安全！尝试使用更复杂的密码"))
	}

	// 加密密码
	hashedPwd, err = util.HashPassword(newPassword)
	if err != nil {
		return "", errors.New(util.LogStr("异常信息: %s", err.Error()))
	}
	return
}

// GetIpv4Addrs 获得IPv4地址列表（仅别名模式）
func (conf *DnsConfig) GetIpv4Addrs() []string {
	return conf.getIpv4AddrsFromAlias()
}

// GetIpv6Addrs 获得IPv6地址列表（仅别名模式）
func (conf *DnsConfig) GetIpv6Addrs() []string {
	return conf.getIpv6AddrsFromAlias()
}

// getIpv4AddrsFromAlias 从别名源域名获取IPv4地址列表
func (conf *DnsConfig) getIpv4AddrsFromAlias() []string {
	if len(conf.Ipv4.Sources) == 0 {
		util.Log("别名模式下未配置源域名列表")
		return nil
	}

	util.Log("别名模式: 开始聚合 %d 个源域名的IPv4地址", len(conf.Ipv4.Sources))
	addrs, err := util.ResolveAliasSourceIPs(conf.Ipv4.Sources, "ipv4")
	if err != nil {
		util.Log("别名聚合失败: %v", err)
		return nil
	}

	return addrs
}

// getIpv6AddrsFromAlias 从别名源域名获取IPv6地址列表
func (conf *DnsConfig) getIpv6AddrsFromAlias() []string {
	if len(conf.Ipv6.Sources) == 0 {
		util.Log("别名模式下未配置源域名列表")
		return nil
	}

	util.Log("别名模式: 开始聚合 %d 个源域名的IPv6地址", len(conf.Ipv6.Sources))
	addrs, err := util.ResolveAliasSourceIPs(conf.Ipv6.Sources, "ipv6")
	if err != nil {
		util.Log("别名聚合失败: %v", err)
		return nil
	}

	return addrs
}

// GetHTTPClient 获得HTTP客户端，如果配置了HttpInterface则绑定到指定网卡
func (conf *DnsConfig) GetHTTPClient() *http.Client {
	return util.CreateHTTPClientWithInterface(conf.HttpInterface)
}
