//go:build !unix

package lib

import "os"

func device(os.FileInfo) (uint64, bool) { return 0, false }
