//go:build !unix && !windows

package sandbox

import "os"

func volumeOf(*os.File) (Volume, error) { return Volume{}, errNoVolume }
