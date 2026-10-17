//go:build !unix

package sandbox

import "os"

// Where folders have no Unix owner and mode, ownership isn't checked.
func checkPrivate(*os.Root, string) (string, error) { return "", nil }
