package fsops

var (
	noSpaceErr     error = errorDiskFull
	quotaErr       error = errorDiskQuotaExceeded
	crossDeviceErr error = errorNotSameDevice
	readOnlyErr    error = errorWriteProtect
)
