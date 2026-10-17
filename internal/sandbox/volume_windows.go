package sandbox

import (
	"os"

	"golang.org/x/sys/windows"
)

func volumeOf(f *os.File) (Volume, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return Volume{}, err
	}
	return Volume{dev: uint64(info.VolumeSerialNumber)}, nil
}
