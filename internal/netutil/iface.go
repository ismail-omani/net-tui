// Package netutil discovers local network interfaces and their IPv4 subnets.
package netutil

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
)

// Iface is one active IPv4 interface.
type Iface struct {
	Name    string
	Addr    net.IP
	Prefix  int
	Network *net.IPNet
	MAC     string
}

// String renders the interface for the TUI list.
func (i Iface) String() string {
	return fmt.Sprintf("%-10s %-18s %s", i.Name, fmt.Sprintf("%s/%d", i.Addr, i.Prefix), i.Network.String())
}

type ipAddrInfo struct {
	Family    string `json:"family"`
	Local     string `json:"local"`
	Prefixlen int    `json:"prefixlen"`
	Scope     string `json:"scope"`
}

type ipLink struct {
	IfName    string       `json:"ifname"`
	OperState string       `json:"operstate"`
	Address   string       `json:"address"`
	AddrInfo  []ipAddrInfo `json:"addr_info"`
}

// List returns active, non-loopback IPv4 interfaces with their subnets.
func List() ([]Iface, error) {
	if out, err := exec.Command("ip", "-j", "addr", "show").Output(); err == nil {
		if ifaces := parseIPJSON(out); len(ifaces) > 0 {
			return ifaces, nil
		}
	}
	return listStdlib()
}

func parseIPJSON(data []byte) []Iface {
	var links []ipLink
	if err := json.Unmarshal(data, &links); err != nil {
		return nil
	}
	var out []Iface
	seen := map[string]bool{}
	for _, l := range links {
		if l.OperState == "DOWN" {
			continue
		}
		if l.IfName == "lo" || strings.HasPrefix(l.IfName, "lo") {
			continue
		}
		for _, a := range l.AddrInfo {
			if a.Family != "inet" || a.Scope != "global" {
				continue
			}
			ip := net.ParseIP(a.Local).To4()
			if ip == nil || a.Prefixlen < 1 || a.Prefixlen > 30 {
				continue
			}
			mask := net.CIDRMask(a.Prefixlen, 32)
			network := &net.IPNet{IP: ip.Mask(mask), Mask: mask}
			key := network.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Iface{
				Name:    l.IfName,
				Addr:    ip,
				Prefix:  a.Prefixlen,
				Network: network,
				MAC:     l.Address,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func listStdlib() ([]Iface, error) {
	netIfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, ni := range netIfaces {
		if ni.Flags&net.FlagUp == 0 || ni.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ni.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil {
				continue
			}
			ones, _ := ipnet.Mask.Size()
			if ones < 1 || ones > 30 {
				continue
			}
			out = append(out, Iface{
				Name:    ni.Name,
				Addr:    ip,
				Prefix:  ones,
				Network: &net.IPNet{IP: ip.Mask(ipnet.Mask), Mask: ipnet.Mask},
				MAC:     ni.HardwareAddr.String(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) == 0 {
		return nil, fmt.Errorf("no active IPv4 interfaces found")
	}
	return out, nil
}

// Find returns the interface matching the given name or containing the IPv4
// address of the target CIDR.
func Find(ifaces []Iface, name, target string) *Iface {
	for i := range ifaces {
		if name != "" && ifaces[i].Name == name {
			return &ifaces[i]
		}
	}
	if target != "" {
		if ip, _, err := net.ParseCIDR(target); err == nil {
			for i := range ifaces {
				if ifaces[i].Network.Contains(ip) {
					return &ifaces[i]
				}
			}
		}
	}
	if len(ifaces) == 1 {
		return &ifaces[0]
	}
	return nil
}

// Private reports whether the CIDR is RFC1918 / link-local / CGNAT space.
func Private(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
