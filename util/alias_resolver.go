package util

import (
	"fmt"
	"net"
	"sort"
)

// ResolveAliasSourceIPs 解析多个源域名的IP地址并去重
// sources: 源域名列表
// ipType: IP类型 "ipv4" 或 "ipv6"
// 返回去重后的IP地址列表
func ResolveAliasSourceIPs(sources []string, ipType string) ([]string, error) {
	if len(sources) == 0 {
		return nil, fmt.Errorf("源域名列表为空")
	}

	// 使用 map 作为 Set 进行自动去重
	ipSet := make(map[string]bool)

	for _, source := range sources {
		Log("正在解析源域名: %s", source)

		// 使用 net.LookupIP 解析域名
		ips, err := net.LookupIP(source)
		if err != nil {
			Log("警告: 无法解析源域名 %s: %v", source, err)
			continue // 跳过失败的域名，继续处理其他域名
		}

		if len(ips) == 0 {
			Log("警告: 源域名 %s 没有返回任何IP地址", source)
			continue
		}

		// 过滤并添加到 Set
		filtered := FilterIPsByType(ips, ipType)
		for _, ip := range filtered {
			if !ipSet[ip] {
				Log("  从 %s 获取到IP: %s", source, ip)
				ipSet[ip] = true
			}
		}
	}

	if len(ipSet) == 0 {
		return nil, fmt.Errorf("所有源域名解析失败或未返回有效的%s地址", ipType)
	}

	// 将 Set 转换为切片
	result := make([]string, 0, len(ipSet))
	for ip := range ipSet {
		result = append(result, ip)
	}

	// 排序以保证结果的确定性
	sort.Strings(result)

	Log("别名聚合完成: 从 %d 个源域名获取到 %d 个唯一的%s地址", len(sources), len(result), ipType)
	return result, nil
}

// FilterIPsByType 根据类型过滤IP地址
// ips: 原始IP地址列表
// ipType: IP类型 "ipv4" 或 "ipv6"
// 返回过滤后的IP地址字符串列表
func FilterIPsByType(ips []net.IP, ipType string) []string {
	var result []string

	for _, ip := range ips {
		// 判断是IPv4还是IPv6
		if ipType == "ipv4" {
			// IPv4: ip.To4() 不为 nil
			if ip.To4() != nil {
				result = append(result, ip.String())
			}
		} else if ipType == "ipv6" {
			// IPv6: ip.To4() 为 nil 且不是IPv4映射的IPv6
			if ip.To4() == nil {
				result = append(result, ip.String())
			}
		}
	}

	return result
}
