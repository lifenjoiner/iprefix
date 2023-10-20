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

func beUint16(ip []byte, i int) uint16 {
	return uint16(ip[2*i])<<8 | uint16(ip[2*i+1])
}

func setbeUint16(ip []byte, i int, v uint16) {
	ip[2*i] = byte(v >> 8)
	ip[2*i+1] = byte(v)
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
		setbeUint16(ip, i, 0xffff)
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
	eb4In6 := ev
	el8 := ev & 0xff
	if el8 != 0xff && el8 != 0 {
		eb4In6 &= 0xff00
	}
	step := uint16(1)
	for i := sv; i <= ev; i += step {
		setbeUint16(ip, block, i)
		addr := netip.AddrFrom16([16]byte(ip))
		ipr := strings.TrimSuffix(addr.String(), tail)
		if is4In6 {
			if step == 1 && i&0xff == 0 && i < eb4In6 {
				step = 0x100
			} else if i >= eb4In6 {
				step = 1
			}
			if step == 0x100 {
				ipr = ipr[:len(ipr)-2]
			}
		}
		dCount := block + 1
		if block < 7 || step == 0x100 {
			if is4In6 {
				ipr += ".*"
			} else {
				ipr += ":*"
			}
			dCount++
		}
		ps = append(ps, ipr)
		prs := strings.Split(ipr, ":")
		pCount := len(prs)
		sCount := dCount - pCount
		zCount := sCount + 1
		mod := false
		if prs[0] == "" {
			prs[0] = "0"
			mod = true
			zCount++
		}
		if zCount < 3 && block < 5 {
			if i == sv {
				for j := 0; j < sCount; j++ {
					ext += ":0"
				}
			}
			for j := 1; j < pCount; j++ {
				if prs[j] == "" {
					prs[j] = ext
					mod = true
					break
				}
			}
			iBlock := block
			// refer test: IPv6z1, IPv6z2
			preZero := 0
			for j := pCount - 2; j >= 0; j-- {
				if prs[j] == "0" {
					preZero++
				} else {
					break
				}
			}
			if preZero > 0 {
				switch preZero {
				case 2:
					// IPv6z2
					if pCount > 3 {
						prs[pCount-3] = ""
						prs[pCount-2] = "*"
						prs = prs[:pCount-1]
						mod = true
						iBlock -= 2
					}
				case 1:
					// IPv6z1
					if pCount == 2 {
						// ::/16
						prs[pCount-1] = ":*"
					} else if mod && pCount > 2 {
						ps = append(ps, strings.Join(prs, ":"))
					}
					prs[pCount-2] = ""
					mod = true
					iBlock--
				}
			}
			if mod {
				if iBlock == 4 {
					// IPv6s3z
					prs[pCount-1] = ":"
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

func processPrefix(p netip.Prefix) (ps []string) {
	addr := p.Addr()
	if p.IsSingleIP() {
		ps = append(ps, addr.String())
		return
	}
	m := p.Bits()
	ip := addr.AsSlice()
	var ipr []string
	if addr.Is4() {
		prefixBlock := int((m - 1) / 8)
		variableBits := m % 8
		if variableBits > 0 || m == 0 {
			// must have a prefix
			variableBits = 8 - variableBits
		}
		sv := ip[prefixBlock] & (0xff << variableBits)
		ev := sv + 1<<variableBits - 1
		ipr = genV4(ip, prefixBlock, sv, ev)
	} else if addr.Is6() {
		prefixBlock := int((m - 1) / 16)
		variableBits := m % 16
		if variableBits > 0 || m == 0 {
			// must have a prefix
			variableBits = 16 - variableBits
		}
		sv := beUint16(ip, prefixBlock) & (0xffff << variableBits)
		ev := sv + 1<<variableBits - 1
		ipr = genV6(ip, prefixBlock, sv, ev, addr.Is4In6())
	}
	ps = append(ps, ipr...)
	return
}

// ProcessCIDR generates string IP prefix pattern from CIDR.
func ProcessCIDR(s string) (ps []string, err error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return
	}
	return processPrefix(p), nil
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
		carry := false
		for i := 3; i >= prefixBlock; i-- {
			if carry {
				ip1[i]++
			}
			if i == prefixBlock {
				break
			}
			vm := ip1[i]
			if vm == 0 {
				continue
			}
			for j := int(vm); j < 0x100; j++ {
				addr := netip.AddrFrom4([4]byte(ip1))
				rs := addr.String()
				if i < 3 {
					rs = rs[:len(rs)-1] + "*"
				}
				ps = append(ps, rs)
				ip1[i]++
			}
			carry = true
		}
		borrow := false
		for i := 3; i >= prefixBlock; i-- {
			if borrow {
				ip2[i]--
			}
			if i == prefixBlock {
				break
			}
			vm := ip2[i]
			if vm == 0xff {
				continue
			}
			for j := int(vm); j >= 0; j-- {
				addr := netip.AddrFrom4([4]byte(ip2))
				rs := addr.String()
				if i < 3 {
					rs = rs[:len(rs)-3] + "*"
				}
				ps = append(ps, rs)
				ip2[i]--
			}
			borrow = true
		}
		if prefixBlock > 0 && ip1[prefixBlock] == 0 && ip2[prefixBlock] == 0xff {
			prefixBlock--
		}
		ipr = genV4(ip1, prefixBlock, ip1[prefixBlock], ip2[prefixBlock])
	} else if addr1.Is6() {
		is4In6 := addr1.Is4In6()
		prefixBlock := 0
		for i := 0; i < 8; i++ {
			if beUint16(ip1, i) == beUint16(ip2, i) {
				prefixBlock++
			} else {
				break
			}
		}
		carry := false
		for i := 7; i >= prefixBlock; i-- {
			vm := beUint16(ip1, i)
			if carry {
				vm++
				setbeUint16(ip1, i, vm)
			}
			if i == prefixBlock {
				break
			}
			if vm == 0 {
				continue
			}
			step := 1
			for j := int(vm); j < 0x10000; j += step {
				addr := netip.AddrFrom16([16]byte(ip1))
				rs := addr.String()
				isIP := true
				if is4In6 {
					if step == 1 && j&0xff == 0 {
						step = 0x100
					}
					if step == 0x100 {
						rs = rs[:len(rs)-1] + "*"
					}
				} else if i < 7 {
					ipri := processPrefix(netip.PrefixFrom(addr, 16*(i+1)))
					ps = append(ps, ipri...)
					isIP = false
				}
				if isIP {
					ps = append(ps, rs)
				}
				vm += uint16(step)
				setbeUint16(ip1, i, vm)
			}
			carry = true
		}
		borrow := false
		for i := 7; i >= prefixBlock; i-- {
			vm := beUint16(ip2, i)
			if borrow {
				vm--
				setbeUint16(ip2, i, vm)
			}
			if i == prefixBlock {
				break
			}
			if vm == 0xffff {
				continue
			}
			step := 1
			for j := int(vm); j >= 0; j -= step {
				addr := netip.AddrFrom16([16]byte(ip2))
				rs := addr.String()
				isIP := true
				if is4In6 {
					if step == 1 && j&0xff == 0xff {
						step = 0x100
					}
					if step == 0x100 {
						rs = rs[:len(rs)-3] + "*"
					}
				} else if i < 7 {
					ipri := processPrefix(netip.PrefixFrom(addr, 16*(i+1)))
					ps = append(ps, ipri...)
					isIP = false
				}
				if isIP {
					ps = append(ps, rs)
				}
				vm -= uint16(step)
				setbeUint16(ip2, i, vm)
			}
			borrow = true
		}
		if prefixBlock > 0 && beUint16(ip1, prefixBlock) == 0 && beUint16(ip2, prefixBlock) == 0xffff {
			prefixBlock--
		}
		sv := beUint16(ip1, prefixBlock)
		ev := beUint16(ip2, prefixBlock)
		ipr = genV6(ip1, prefixBlock, sv, ev, is4In6)
	}
	ps = append(ps, ipr...)
	return
}
