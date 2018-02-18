// +build !windows

package caps

import (
	"fmt"
	"strings"

	"github.com/syndtr/gocapability/capability"
)

var capabilityList Capabilities

func init() {
	last := capability.CAP_LAST_CAP
	// hack for RHEL6 which has no /proc/sys/kernel/cap_last_cap
	if last == capability.Cap(63) {
		last = capability.CAP_BLOCK_SUSPEND
	}
	// 将所有的capability加载到capabilityList中
	for _, cap := range capability.List() {
		if cap > last {
			continue
		}
		capabilityList = append(capabilityList,
			&CapabilityMapping{
				Key:   "CAP_" + strings.ToUpper(cap.String()),
				Value: cap,
			},
		)
	}
}

type (
	// CapabilityMapping maps linux capability name to its value of capability.Cap type
	// Capabilities is one of the security systems in Linux Security Module (LSM)
	// framework provided by the kernel.
	// For more details on capabilities, see http://man7.org/linux/man-pages/man7/capabilities.7.html
	// CapabilityMapping将linux capability name映射到对应的capability.Cap类型
	// Capabilities是Linux Security Module(LSM)的一种security systems
	CapabilityMapping struct {
		Key   string         `json:"key,omitempty"`
		Value capability.Cap `json:"value,omitempty"`
	}
	// Capabilities contains all CapabilityMapping
	Capabilities []*CapabilityMapping
)

// String returns <key> of CapabilityMapping
func (c *CapabilityMapping) String() string {
	return c.Key
}

// GetCapability returns CapabilityMapping which contains specific key
func GetCapability(key string) *CapabilityMapping {
	for _, capp := range capabilityList {
		if capp.Key == key {
			cpy := *capp
			return &cpy
		}
	}
	return nil
}

// GetAllCapabilities returns all of the capabilities
// GetAllCapabilities返回所有的capabilities
func GetAllCapabilities() []string {
	output := make([]string, len(capabilityList))
	for i, capability := range capabilityList {
		output[i] = capability.String()
	}
	return output
}

// inSlice tests whether a string is contained in a slice of strings or not.
// Comparison is case insensitive
// inSlice检测string是否在一个string slice中，对比是大小写敏感的
func inSlice(slice []string, s string) bool {
	for _, ss := range slice {
		if strings.ToLower(s) == strings.ToLower(ss) {
			return true
		}
	}
	return false
}

// TweakCapabilities can tweak capabilities by adding or dropping capabilities
// based on the basics capabilities.
func TweakCapabilities(basics, adds, drops []string) ([]string, error) {
	var (
		newCaps []string
		allCaps = GetAllCapabilities()
	)

	// FIXME(tonistiigi): docker format is without CAP_ prefix, oci is with prefix
	// Currently they are mixed in here. We should do conversion in one place.
	// 在docker中没有CAP作为prefix，但是在oci中有
	// 现在它们都混合在一起了

	// look for invalid cap in the drop list
	// 查看drop list中是否存在不合法的cap
	for _, cap := range drops {
		if strings.ToLower(cap) == "all" {
			continue
		}

		// 存在未知的CAP就报错
		if !inSlice(allCaps, "CAP_"+cap) {
			return nil, fmt.Errorf("Unknown capability drop: %q", cap)
		}
	}

	// handle --cap-add=all
	// 先处理--cap-add=all的情况
	if inSlice(adds, "all") {
		// 如果--cap-add中存在all，则将basic设置为所有的caps
		basics = allCaps
	}

	// 如果drops中不包含all
	if !inSlice(drops, "all") {
		for _, cap := range basics {
			// skip `all` already handled above
			if strings.ToLower(cap) == "all" {
				continue
			}

			// if we don't drop `all`, add back all the non-dropped caps
			// 先将所有没在drops中的basic，加入newCaps
			if !inSlice(drops, cap[4:]) {
				newCaps = append(newCaps, strings.ToUpper(cap))
			}
		}
	}

	for _, cap := range adds {
		// skip `all` already handled above
		if strings.ToLower(cap) == "all" {
			continue
		}

		cap = "CAP_" + cap

		// 如果add的cap不在合法的capability中
		if !inSlice(allCaps, cap) {
			return nil, fmt.Errorf("Unknown capability to add: %q", cap)
		}

		// add cap if not already in the list
		// 将adds中的所有cap加入
		if !inSlice(newCaps, cap) {
			newCaps = append(newCaps, strings.ToUpper(cap))
		}
	}
	return newCaps, nil
}
