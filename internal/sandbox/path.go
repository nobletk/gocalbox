package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
)

func SecureJoin(rootDir, userPath string) (string, error) {
	cleanRoot := filepath.Clean(rootDir)

	cleanUser := filepath.Clean(userPath)

	finalPath := filepath.Join(cleanRoot, cleanUser)

	prefixCheck := cleanRoot + string(filepath.Separator)

	if !strings.HasPrefix(finalPath, prefixCheck) && finalPath != cleanRoot {
		return "", fmt.Errorf("security violation: path traversal attempt detected")
	}

	return finalPath, nil
}
