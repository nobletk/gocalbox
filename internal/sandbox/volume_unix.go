//go:build unix

package sandbox

import (
	"os"
	"syscall"
)

func volumeOfStat(f *os.File) (Volume, error) {
	fi, err := f.Stat()
	if err != nil {
		return Volume{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return Volume{}, errNoVolume
	}
	return Volume{dev: uint64(st.Dev)}, nil
}
