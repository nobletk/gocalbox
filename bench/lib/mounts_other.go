//go:build !linux

package lib

// mountedOnTheWay reports false: elsewhere a mount inside the folder is told
// by its device number, and on Windows links and reparse points are never
// entered.
func mountedOnTheWay(dir, p string) (bool, error) { return false, nil }
