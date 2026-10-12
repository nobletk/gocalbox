package space

import (
	"os"
	"syscall"
	"unsafe"
)

var procGetDiskFreeSpaceExW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetDiskFreeSpaceExW")

// Free reports the bytes available to the server's user, quotas included, on
// the volume holding dir.
func Free(dir *os.File) (int64, error) {
	p, err := syscall.UTF16PtrFromString(dir.Name())
	if err != nil {
		return 0, err
	}
	var avail, total, totalFree uint64
	r, _, callErr := procGetDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&avail)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&totalFree)),
	)
	if r == 0 {
		return 0, callErr
	}
	return clamp(avail, 1), nil
}
