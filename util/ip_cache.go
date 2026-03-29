package util

import (
	"os"
	"sort"
	"strconv"
)

const IPCacheTimesENV = "DDNS_IP_CACHE_TIMES"

// IpCache 上次IP缓存
type IpCache struct {
	Addr          string   // 缓存地址（单个，用于向后兼容）
	Addrs         []string // 缓存地址列表（支持多IP）
	Times         int      // 剩余次数
	TimesFailedIP int      // 获取ip失败的次数
}

var ForceCompareGlobal = true

func (d *IpCache) Check(newAddr string) bool {
	if newAddr == "" {
		return true
	}
	// 地址改变 或 达到剩余次数
	if d.Addr != newAddr || d.Times <= 1 {
		IPCacheTimes, err := strconv.Atoi(os.Getenv(IPCacheTimesENV))
		if err != nil {
			IPCacheTimes = 5
		}
		d.Addr = newAddr
		d.Times = IPCacheTimes + 1
		return true
	}
	d.Addr = newAddr
	d.Times--
	return false
}

// CheckAddrs 检查IP地址列表是否改变（支持多IP）
func (d *IpCache) CheckAddrs(newAddrs []string) bool {
	if len(newAddrs) == 0 {
		return true
	}

	// 排序新地址列表用于比较
	sortedNewAddrs := make([]string, len(newAddrs))
	copy(sortedNewAddrs, newAddrs)
	sort.Strings(sortedNewAddrs)

	// 排序缓存的地址列表
	sortedCachedAddrs := make([]string, len(d.Addrs))
	copy(sortedCachedAddrs, d.Addrs)
	sort.Strings(sortedCachedAddrs)

	// 比较地址列表是否相同
	addrsChanged := !stringSlicesEqual(sortedNewAddrs, sortedCachedAddrs)

	// 地址改变 或 达到剩余次数
	if addrsChanged || d.Times <= 1 {
		IPCacheTimes, err := strconv.Atoi(os.Getenv(IPCacheTimesENV))
		if err != nil {
			IPCacheTimes = 5
		}
		d.Addrs = newAddrs
		if len(newAddrs) > 0 {
			d.Addr = newAddrs[0] // 向后兼容：保存第一个IP
		}
		d.Times = IPCacheTimes + 1
		return true
	}

	d.Addrs = newAddrs
	if len(newAddrs) > 0 {
		d.Addr = newAddrs[0]
	}
	d.Times--
	return false
}

// stringSlicesEqual 比较两个字符串切片是否相等
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
