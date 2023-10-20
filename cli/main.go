// Copyright 2023-now by lifenjoiner. All rights reserved.
// Use of this source code is governed by a MIT license
// that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lifenjoiner/iprefix"
)

func processLine(s string, cc string) {
	ss := strings.TrimSpace(s)
	if len(ss) == 0 || ss[:len(cc)] == cc {
		fmt.Printf("%s\n", s)
		return
	}

	ss = strings.Replace(ss, "\t", " ", 1)
	p := strings.SplitN(ss, " ", 2)
	x := strings.TrimSpace(p[0])

	var pr []string
	var err error
	if strings.ContainsRune(x, '/') {
		pr, err = iprefix.ProcessCIDR(x)
	} else {
		r := strings.SplitN(x, "-", 2)
		switch len(r) {
		case 2:
			pr, err = iprefix.ProcessRange(r[0], r[1])
		case 1:
			fmt.Printf("%s\n", s)
			return
		}
	}
	if err != nil {
		fmt.Printf("%s\n", s)
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return
	}
	fmt.Printf("%s %s\n", cc, ss)
	for _, ipr := range pr {
		fmt.Printf("%s\n", ipr)
	}
}

func main_int() int {
	var cc string
	var file string

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [-c char] [-f file]|[CIDR]|[IP1-IP2]\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&file, "f", "", "input file path")
	flag.StringVar(&cc, "c", "#", "comment character")
	flag.Parse()

	args := flag.Args()
	if len(file) > 0 {
		b, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		x := len(b)
		switch b[x-1] {
		case '\n':
			b = b[:x-1]
			if b[x-2] == '\r' {
				b = b[:x-2]
			}
		case '\r':
			b = b[:x-1]
		}
		lines := strings.Split(string(b), "\n")
		for _, line := range lines {
			processLine(strings.TrimSpace(line), cc)
		}
	} else if len(args) > 0 {
		processLine(args[0], cc)
	} else {
		flag.Usage()
		return 1
	}
	return 0
}

func main() {
	os.Exit(main_int())
}
