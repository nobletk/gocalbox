//go:build !unix

package fsops

import (
	"io/fs"
	"os"
)

const openNonblock = 0

func clearNonblock(*os.File) error { return nil }

func fileID(fs.FileInfo) (dev, ino uint64) { return 0, 0 }
