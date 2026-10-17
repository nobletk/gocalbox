package fsops

import (
	"errors"

	"golang.org/x/sys/unix"
)

// mayWrite asks the kernel whether the server may write in the folder fd,
// with its effective user ID and capabilities. faccessat2 is missing before
// Linux 5.8 and under some seccomp filters, which then answer ENOSYS or
// EPERM; EPERM also means an immutable folder, which the plain call, asking
// for the real user ID, refuses again. x/sys's own fallback is avoided: it
// answers from the mode bits, which allow root anything.
func mayWrite(fd int) error {
	err := unix.Faccessat2(fd, ".", unix.W_OK, unix.AT_EACCESS)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		err = unix.Faccessat(fd, ".", unix.W_OK, 0)
	}
	return err
}
