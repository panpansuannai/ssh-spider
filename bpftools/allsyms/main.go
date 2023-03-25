package main

import (
	"flag"
	"fmt"
)

const sshd = "/usr/sbin/sshd"
const libc = "/usr/lib/x86_64-linux-gnu/libc.so.6"

func main() {
	path := ""
	flag.StringVar(&path, "path", "", "name")
	flag.Parse()

	if path == "sshd" {
		path = sshd
	}
	if path == "libc" {
		path = libc
	}

	e, err := OpenExecutable(path)
	if err != nil {
		fmt.Println("Open ", path, " error: ", err)
	}
	for s, addr := range e.addresses {
		if addr != 0 {
			fmt.Println(s)
		}
	}
}
