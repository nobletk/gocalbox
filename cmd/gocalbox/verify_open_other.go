//go:build !unix

package main

import "os"

func openToVerify(path string) (*os.File, error) { return os.Open(path) }
