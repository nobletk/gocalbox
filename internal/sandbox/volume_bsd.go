//go:build unix && !linux

package sandbox

import "os"

func volumeOf(f *os.File) (Volume, error) { return volumeOfStat(f) }
