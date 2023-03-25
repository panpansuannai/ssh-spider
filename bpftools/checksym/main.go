package main

import (
	"flag"
	"fmt"
)

const sshd = "/usr/sbin/sshd"
const libc = "/usr/lib/x86_64-linux-gnu/libc.so.6"

func main() {
	path := ""
	sym := ""
	flag.StringVar(&path, "path", "", "name")
	flag.StringVar(&sym, "sym", "", "symbol")
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
	_, err = e.address(sym, &UprobeOptions{})
	if err != nil {
		fmt.Println(err)
	}
}
