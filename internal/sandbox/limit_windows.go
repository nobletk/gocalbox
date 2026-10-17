package sandbox

import (
	"os"

	"golang.org/x/sys/windows"
)

func fileSizeLimit(f *os.File) int64 {
	var name [windows.MAX_PATH + 1]uint16
	if windows.GetVolumeInformationByHandle(windows.Handle(f.Fd()), nil, 0, nil, nil, nil, &name[0], uint32(len(name))) != nil {
		return 0
	}
	switch windows.UTF16ToString(name[:]) {
	case "FAT", "FAT32":
		return fat32Limit
	}
	return 0
}
