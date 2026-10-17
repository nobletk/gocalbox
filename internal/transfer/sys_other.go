//go:build !unix && !windows

package transfer

import "os"

func syncDir(*os.Root, string) error { return nil }

func isNoSpace(error) bool { return false }

func isTooBig(error) bool { return false }
