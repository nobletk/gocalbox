//go:build !linux && !darwin && !windows

package space

import (
	"errors"
	"os"
)

func Free(*os.File) (int64, error) { return 0, errors.ErrUnsupported }
