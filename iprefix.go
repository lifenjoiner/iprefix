// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// Package iprefix expands CIDR or IP range to string IP prefix patterns.
package iprefix

import (
	"fmt"
	"net/netip"
	"strings"
)

func ipv6Uint16(ip []byte, i int) uint16 {
	return uint16(ip[2*i])<<8 | uint16(ip[2*i+1])
}

func setIpv6Uint16(ip []byte, i int, v uint16) {
	ip[2*i] = byte((v >> 8) & 0xffff)
	ip[2*i+1] = byte(v & 0xffff)
}

func genV4(ip []byte, block int, sv, ev uint8) (ps []string) {
	for i := sv; i <= ev; i++ {
		ip[block] = i
		ipr := ""
		for j := 0; j <= block; j++ {
			ipr += fmt.Sprintf("%d", ip[j])
			if j < 3 {
				ipr += "."
			}
		}
		if block < 3 {
			ipr += "*"
		}
		ps = append(ps, ipr)
		if i == ev {
			break
		}
	}
	return
}

func genV6(ip []byte, block int, sv, ev uint16, is4In6 bool) (ps []string) {
	tail := ""
	for i := block + 1; i < 8; i++ {
		setIpv6Uint16(ip, i, 0xffff)
		if is4In6 {
			switch i {
			case 6:
				tail += ":255.255"
			case 7:
				tail += ".255.255"
			}
		} else {
			tail += ":ffff"
		}
	}
	ext := "0"
	for i := sv; i <= ev; i++ {
		setIpv6Uint16(ip, block, i)
		addr := netip.AddrFrom16([16]byte(ip))
		ipr := strings.TrimSuffix(addr.String(), tail)
		x := block + 1
		if block < 7 {
			ipr += ":*"
			x++
		}
		ps = append(ps, ipr)
		prs := strings.Split(ipr, ":")
		if len(prs) <= x && block < 5 {
			mod := false
			if i == sv {
				for j := 0; j < x-len(prs); j++ {
					ext += ":0"
				}
			}
			if prs[0] == "" {
				prs[0] = "0"
				mod = true
			}
			for j := 1; j < len(prs); j++ {
				if prs[j] == "" {
					prs[j] = ext
					mod = true
					break
				}
			}
			iBlock := block
			// refer test: IPv6z1, IPv6z2
			pz := 0
			for j := len(prs) - 2; j >= 0; j-- {
				if prs[j] == "0" {
					pz++
				} else {
					break
				}
			}
			if pz > 0 {
				x := len(prs)
				switch pz {
				case 2:
					// IPv6z2
					if x > 3 {
						prs[x-3] = ""
						prs[x-2] = "*"
						prs = prs[:x-1]
						mod = true
						iBlock -= 2
					}
				case 1:
					// IPv6z1
					if x == 2 {
						// ::/16
						prs[x-1] = ":*"
					} else if mod && x > 2 {
						ps = append(ps, strings.Join(prs, ":"))
					}
					prs[x-2] = ""
					mod = true
					iBlock--
				}
			}
			if mod {
				if iBlock == 4 {
					// IPv6s3z
					prs[len(prs)-1] = ":"
				}
				ps = append(ps, strings.Join(prs, ":"))
			}
		}
		if i == ev {
			break
		}
	}
	return
}

// ProcessCIDR generates string IP prefix pattern from CIDR.
func ProcessCIDR(s string) (ps []string, err error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return
	}
	m := p.Bits()
	addr := p.Addr()
	if p.IsSingleIP() {
		ps = append(ps, addr.String())
		return
	}
	ip := addr.AsSlice()
	var ipr []string
	if addr.Is4() {
		prefixBlock := int((m - 1) / 8)
		variableBits := m % 8
		if variableBits > 0 || m == 0 {
			variableBits = 8 - variableBits
		}
		sv := ip[prefixBlock] & (0xff << variableBits)
		ev := sv + 1<<variableBits - 1
		ipr = genV4(ip, prefixBlock, sv, ev)
	} else if addr.Is6() {
		prefixBlock := int((m - 1) / 16)
		variableBits := m % 16
		if variableBits > 0 || m == 0 {
			variableBits = 16 - variableBits
		}
		sv := ipv6Uint16(ip, prefixBlock) & (0xffff << variableBits)
		ev := sv + 1<<variableBits - 1
		ipr = genV6(ip, prefixBlock, sv, ev, addr.Is4In6())
	}
	ps = append(ps, ipr...)
	return
}

// ProcessRange generates string IP prefix pattern from IP range.
// `s` is start IP. `e` is end IP.
func ProcessRange(s, e string) (ps []string, err error) {
	addr1, err := netip.ParseAddr(s)
	if err != nil {
		return
	}
	addr2, err := netip.ParseAddr(e)
	if err != nil {
		return
	}
	if addr1.BitLen() != addr2.BitLen() {
		err = fmt.Errorf("not the same type: %v Vs %v", addr1, addr2)
		return
	}
	switch addr1.Compare(addr2) {
	case 1:
		err = fmt.Errorf("%v > %v", addr1, addr2)
		return
	case 0:
		ps = append(ps, s)
		return
	}
	ip1 := addr1.AsSlice()
	ip2 := addr2.AsSlice()
	var ipr []string
	if addr1.Is4() {
		prefixBlock := 0
		for i := 0; i < 4; i++ {
			if ip1[i] == ip2[i] {
				prefixBlock++
			} else {
				break
			}
		}
		sb := false
		for i := 3; i > prefixBlock; i-- {
			vm := ip1[i]
			if vm == 0 {
				continue
			}
			for j := int(vm); j < 0x100; j++ {
				addr := netip.AddrFrom4([4]byte(ip1))
				ps = append(ps, addr.String())
				ip1[i]++
				sb = true
			}
		}
		if sb {
			ip1[prefixBlock]++
		}
		eb := false
		for i := 3; i > prefixBlock; i-- {
			vm := ip2[i]
			if vm == 0xff {
				continue
			}
			for j := int(vm); j >= 0; j-- {
				addr := netip.AddrFrom4([4]byte(ip2))
				ps = append(ps, addr.String())
				ip2[i]--
				eb = true
			}
		}
		if eb {
			ip2[prefixBlock]--
		}
		if prefixBlock > 0 && ip1[prefixBlock] == 0 && ip2[prefixBlock] == 0xff {
			prefixBlock--
		}
		ipr = genV4(ip1, prefixBlock, ip1[prefixBlock], ip2[prefixBlock])
	} else if addr1.Is6() {
		prefixBlock := 0
		for i := 0; i < 8; i++ {
			if ipv6Uint16(ip1, i) == ipv6Uint16(ip2, i) {
				prefixBlock++
			} else {
				break
			}
		}
		sb := false
		for i := 7; i > prefixBlock; i-- {
			vm := ipv6Uint16(ip1, i)
			if vm == 0 {
				continue
			}
			for j := int(vm); j < 0x10000; j++ {
				addr := netip.AddrFrom16([16]byte(ip1))
				ps = append(ps, addr.String())
				vm++
				setIpv6Uint16(ip1, i, vm)
				sb = true
			}
		}
		if sb {
			v := ipv6Uint16(ip1, prefixBlock)
			v++
			setIpv6Uint16(ip1, prefixBlock, v)
		}
		eb := false
		for i := 7; i > prefixBlock; i-- {
			vm := ipv6Uint16(ip2, i)
			if vm == 0xffff {
				continue
			}
			for j := int(vm); j >= 0; j-- {
				addr := netip.AddrFrom16([16]byte(ip2))
				ps = append(ps, addr.String())
				vm--
				setIpv6Uint16(ip2, i, vm)
				eb = true
			}
		}
		if eb {
			v := ipv6Uint16(ip2, prefixBlock)
			v--
			setIpv6Uint16(ip2, prefixBlock, v)
		}
		if prefixBlock > 0 && ipv6Uint16(ip1, prefixBlock) == 0 && ipv6Uint16(ip2, prefixBlock) == 0xffff {
			prefixBlock--
		}
		sv := ipv6Uint16(ip1, prefixBlock)
		ev := ipv6Uint16(ip2, prefixBlock)
		ipr = genV6(ip1, prefixBlock, sv, ev, addr1.Is4In6())
	}
	ps = append(ps, ipr...)
	return
}
