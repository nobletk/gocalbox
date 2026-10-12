//go:build !unix && !windows

package fsops

func isNoSpace(error) bool { return false }

func isCrossDevice(error) bool { return false }

func isReadOnly(error) bool { return false }
