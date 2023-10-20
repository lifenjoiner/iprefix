// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

// Package iprefix expands CIDR or IP range to string IP prefix patterns.
package iprefix

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

type Test struct {
	CIDR     string
	Range    string
	Expected any
}

var test []Test

func prepareExpected() {
	if len(test) > 0 {
		return
	}

	var t Test
	err := fmt.Errorf("not nil")

	// IPv4
	t = Test{CIDR: "127.0.0.1/0", Range: "127.0.0.1-255.255.255.255"}
	{
		r := [256]string{}
		for i := 0; i < 256; i++ {
			r[i] = fmt.Sprintf("%d", i) + ".*"
		}
		t.Expected = r
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/7", Range: "126.0.0.0-127.255.255.255"}
	{
		r := [2]string{}
		for i := 0; i < 2; i++ {
			r[i] = fmt.Sprintf("%d", 126+i) + ".*"
		}
		t.Expected = r
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/8", Range: "127.0.0.0-127.255.255.255"}
	{
		t.Expected = []string{"127.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/14", Range: "127.0.0.0-127.3.255.255"}
	{
		r := [4]string{}
		for i := 0; i < 4; i++ {
			r[i] = "127." + fmt.Sprintf("%d", i) + ".*"
		}
		t.Expected = r
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/30", Range: "127.0.0.0-127.0.0.3"}
	{
		r := [4]string{}
		for i := 0; i < 4; i++ {
			r[i] = "127.0.0." + fmt.Sprintf("%d", i)
		}
		t.Expected = r
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/32", Range: "127.0.0.1-127.0.0.1"}
	{
		t.Expected = []string{"127.0.0.1"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "10.0.0.254-10.0.2.1"}
	{
		t.Expected = []string{"10.0.0.254", "10.0.0.255", "10.0.2.1", "10.0.2.0", "10.0.1.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "10.0.254.255-10.2.2.0"}
	{
		t.Expected = []string{"10.0.254.255", "10.0.255.*", "10.2.2.0", "10.2.1.*", "10.2.0.*", "10.1.*"}
		test = append(test, t)
	}

	// IPv4 error
	t = Test{CIDR: "1271.0.0.1/32", Range: "1271.0.0.1-127.0.0.1"}
	{
		t.Expected = err
		test = append(test, t)
	}

	t = Test{CIDR: "127.0.0.1/-1", Range: "127.0.0.2-127.0.0.1"}
	{
		t.Expected = err
		test = append(test, t)
	}

	// IPv6
	t = Test{CIDR: "::/128", Range: "::-::"}
	{
		t.Expected = [1]string{"::"}
		test = append(test, t)
	}

	t = Test{CIDR: "::1/128", Range: "::1-::1"}
	{
		t.Expected = []string{"::1"}
		test = append(test, t)
	}

	t = Test{CIDR: "::1/127", Range: "::-::1"}
	{
		t.Expected = []string{"::", "::1"}
		test = append(test, t)
	}

	t = Test{CIDR: "::ffff:192.168.0.1/112", Range: "::ffff:192.168.0.0-::ffff:192.168.255.255"}
	{
		t.Expected = []string{"::ffff:192.168.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "2001:20::/28", Range: "2001:20::-2001:2f:ffff:ffff:ffff:ffff:ffff:ffff"}
	{
		r := [16]string{}
		for i := 0; i < 16; i++ {
			r[i] = "2001:" + fmt.Sprintf("%d", 20+i) + ":*"
		}
		t.Expected = r
		test = append(test, t)
	}

	t = Test{CIDR: "2001:20::/111", Range: "2001:20::-2001:20::1:ffff"}
	{
		t.Expected = []string{"2001:20::*", "2001:20::1:*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::ffff:ffff-::2:0:0"}
	{
		t.Expected = []string{"::ffff:ffff", "::2:0:0", "::1:*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::fffe:ffff:ffff-::2:1:0:0"}
	{
		t.Expected = []string{"::fffe:ffff:ffff", "::ffff.*", "::2:1:0:0", "::2:0:*", "::1:*"}
		test = append(test, t)
	}

	// IPv6z1
	t = Test{CIDR: "0:0:0:0:0:0:0:0/16", Range: "::-0:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	{
		// 00:2:0:0:0:0:7:8, 00:0:3:4:5:6:7:8
		// 0:2::, ::3:4:5:6:7:8
		// 0:*, ::*
		t.Expected = []string{"0:*", "::*"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111:0:0:0:0:0:0:0/32", Range: "1111::-1111:0:ffff:ffff:ffff:ffff:ffff:ffff"}
	{
		// 1111:00:3:0:0:0:7:8, 1111:00:0:0:5:6:7:8
		// 1111:0:3::, 1111::5:6:7:8
		// 1111:0:*, 1111::*
		t.Expected = []string{"1111:0:*", "1111::*"}
		test = append(test, t)
	}

	t = Test{CIDR: "0:0:3333:0:0:0:0:0/64", Range: "0:0:3333::-0:0:3333:0:ffff:ffff:ffff:ffff"}
	{
		// 0:0:3333:00:5:6:7:8, 0:0:3333:00:5:0:0:0, 0:0:3333:00:0:0:7:8
		// ::3333:0:5:6:7:8, 0:0:3333:0:5::, 0:0:3333::7:8
		// ::3333:0:*, 0:0:3333:0:*, 0:0:3333::*
		t.Expected = []string{"::3333:0:*", "0:0:3333:0:*", "0:0:3333::*"}
		test = append(test, t)
	}

	// IPv6z2
	t = Test{CIDR: "0:0:0:0:0:0:0:0/32", Range: "::-0:0:ffff:ffff:ffff:ffff:ffff:ffff"}
	{
		// 00:00:3:0:0:0:7:8, 00:00:0:4:5:6:7:8
		// 0:0:3::, ::4:5:6:7:8
		// 0:0:*, ::*
		t.Expected = []string{"0:0:*", "::*"}
		test = append(test, t)
	}

	t = Test{CIDR: "0:0:3333:0:0:0:0:0/80", Range: "0:0:3333::-0:0:3333:0:0:ffff:ffff:ffff"}
	{
		// 0:0:3333:00:00:6:7:8, 0:0:3333:00:00:0:7:8, 0:0:3333:00:00:0:0:8
		// ::3333:0:0:6:7:8, 0:0:3333::7:8, 0:0:3333::8
		// ::3333:0:0:*, 0:0:3333::*
		t.Expected = []string{"::3333:0:0:*", "0:0:3333::*"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111:0:0:0:0:0:0:0/48", Range: "1111::-1111:0:0:ffff:ffff:ffff:ffff:ffff"}
	{
		// 1111:00:00:4:0:0:0:8, 1111:00:00:0:5:6:7:8
		// 1111:0:0:4::8, 1111::5:6:7:8
		// 1111:0:0:*, 1111::*
		t.Expected = []string{"1111:0:0:*", "1111::*"}
		test = append(test, t)
	}

	//
	t = Test{CIDR: "0:0:3333:0:0:0:0:0/48", Range: "0:0:3333::-0:0:3333:ffff:ffff:ffff:ffff:ffff"}
	{
		t.Expected = []string{"::3333:*", "0:0:3333:*"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111::4444:5555:6666:7777:8888/64", Range: "1111:0:0:4444::-1111::4444:ffff:ffff:ffff:ffff"}
	{
		t.Expected = []string{"1111::4444:*", "1111:0:0:4444:*"}
		test = append(test, t)
	}

	// IPv6s3z
	t = Test{CIDR: "1111:0:0:4444:5555:6666:7777:8888/80", Range: "1111:0:0:4444:5555::-1111:0:0:4444:5555:ffff:ffff:ffff"}
	{
		// 1111:0:0:4444:5555:6:0:0, 1111:0:0:4444:5555:0:0:8, 1111:0:0:4444:5555:0:0:0
		// 1111::4444:5555:6:0:0, 1111::4444:5555:0:0:8, 1111:0:0:4444:5555::
		// 1111::4444:5555:*, 1111:0:0:4444:5555::
		t.Expected = []string{"1111::4444:5555:*", "1111:0:0:4444:5555::"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111:0:0:4444:5555:6666:7777:8888/96", Range: "1111:0:0:4444:5555:6666:0:0-1111:0:0:4444:5555:6666:ffff:ffff"}
	{
		t.Expected = []string{"1111::4444:5555:6666:*"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111::4444:5555:6666:7777:8888/127", Range: "1111::4444:5555:6666:7777:8888-1111::4444:5555:6666:7777:8889"}
	{
		t.Expected = []string{"1111::4444:5555:6666:7777:8888", "1111::4444:5555:6666:7777:8889"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "1111::4444:5555:6666:7777:ffff-1111::4444:5555:6666:7779:0"}
	{
		t.Expected = []string{"1111::4444:5555:6666:7777:ffff", "1111::4444:5555:6666:7779:0", "1111::4444:5555:6666:7778:*"}
		test = append(test, t)
	}

	t = Test{CIDR: "1111::4444:5555:6666:7777:8888/128", Range: "1111::4444:5555:6666:7777:8888-1111::4444:5555:6666:7777:8888"}
	{
		t.Expected = []string{"1111::4444:5555:6666:7777:8888"}
		test = append(test, t)
	}

	// 4in6

	t = Test{CIDR: "::ffff:a00:0/104", Range: "::ffff:10.0.0.0-::ffff:10.255.255.255"}
	{
		t.Expected = []string{"::ffff:10.*"}
		test = append(test, t)
	}
	t = Test{CIDR: "::ffff:a00:0/111", Range: "::ffff:10.0.0.0-::ffff:10.1.255.255"}
	{
		t.Expected = []string{"::ffff:10.0.*", "::ffff:10.1.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "::ffff:ac10:0/127", Range: "::ffff:172.16.0.0-::ffff:172.16.0.1"}
	{
		t.Expected = []string{"::ffff:172.16.0.0", "::ffff:172.16.0.1"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::ffff:10.0.255.255-::ffff:10.2.0.0"}
	{
		t.Expected = []string{"::ffff:10.0.255.255", "::ffff:10.2.0.0", "::ffff:10.1.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::ffff:10.0.254.255-::ffff:10.2.2.0"}
	{
		t.Expected = []string{"::ffff:10.0.254.255", "::ffff:10.0.255.*", "::ffff:10.2.2.0", "::ffff:10.2.1.*", "::ffff:10.2.0.*", "::ffff:10.1.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::ffff:10.1.0.0-::ffff:10.1.1.255"}
	{
		t.Expected = []string{"::ffff:10.1.0.*", "::ffff:10.1.1.*"}
		test = append(test, t)
	}

	t = Test{CIDR: "", Range: "::ffff:10.0.0.0-::ffff:10.1.255.255"}
	{
		t.Expected = []string{"::ffff:10.0.*", "::ffff:10.1.*"}
		test = append(test, t)
	}

	// IPv6 error
	t = Test{CIDR: "1111::4444::/127", Range: "1111::4444:5555:6666:7777:88888-1111::4444:5555:6666:7777:8889"}
	{
		t.Expected = err
		test = append(test, t)
	}

	t = Test{CIDR: "1111::4444:5555:6666:7777:8888/1277", Range: "1111::4444:5555:6666:7777:8888-1111::4444:5555:6666:7777:889"}
	{
		t.Expected = err
		test = append(test, t)
	}
}

func validate(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sort.SliceStable(a, func(i, j int) bool {
		return a[i] < a[j]
	})
	sort.SliceStable(b, func(i, j int) bool {
		return b[i] < b[j]
	})
	return strings.Join(a, "\n") == strings.Join(b, "\n")
}

func TestProcessCIDR(t *testing.T) {
	prepareExpected()
	for _, mt := range test {
		if len(mt.CIDR) == 0 {
			continue
		}
		r, err := ProcessCIDR(mt.CIDR)
		switch d := mt.Expected.(type) {
		case []string:
			if !validate(r, d) {
				fmt.Printf("%s\n", mt.CIDR)
				fmt.Printf("%s\n\n", strings.Join(r, "\n"))
				t.Error(mt.CIDR)
			}
		case error:
			if err == nil {
				t.Error(mt.CIDR)
			}
		}
	}
}

func TestProcessRange(t *testing.T) {
	prepareExpected()
	for _, mt := range test {
		if len(mt.Range) == 0 {
			continue
		}
		rg := strings.Split(mt.Range, "-")
		r, err := ProcessRange(rg[0], rg[1])
		switch d := mt.Expected.(type) {
		case []string:
			if !validate(r, d) {
				fmt.Printf("%s\n", mt.Range)
				fmt.Printf("%s\n\n", strings.Join(r, "\n"))
				t.Error(mt.Range)
			}
		case error:
			if err == nil {
				t.Error(mt.Range)
			}
		}
	}
}
