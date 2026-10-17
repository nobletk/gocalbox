//go:build !unix

package fsops

import (
	"io/fs"
	"os"
)

const openNonblock = 0

func clearNonblock(*os.File) error { return nil }

func fileID(fs.FileInfo) (dev, ino uint64) { return 0, 0 }

func writable(*os.Root, string) error { return nil }

// Go opens a folder on Windows with a handle that can't be flushed; NTFS's
// own journal is all that makes a new entry durable there.
func syncDir(*os.Root, string) error { return nil }
