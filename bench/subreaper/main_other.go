//go:build !linux

// Command subreaper is for Linux only, where it runs the benchmark's sshd.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "subreaper runs on Linux only")
	os.Exit(1)
}
