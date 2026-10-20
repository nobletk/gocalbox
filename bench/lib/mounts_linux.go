package lib

import (
	"bufio"
	"os"
	"strings"
)

// mountTable is the mount table read; tests point it elsewhere.
var mountTable = "/proc/self/mountinfo"

// mountedOnTheWay reports whether a file system is mounted inside dir at p,
// inside p, or on the way from dir to p. A bind mount of dir's own file
// system has its device number, so only the mount table tells.
func mountedOnTheWay(dir, p string) (bool, error) {
	f, err := os.Open(mountTable)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		t := unescapeMount(fields[4])
		if !strings.HasPrefix(t, dir+"/") {
			continue
		}
		if t == p || strings.HasPrefix(t, p+"/") || strings.HasPrefix(p, t+"/") {
			return true, nil
		}
	}
	return false, sc.Err()
}

// unescapeMount reads the octal escapes /proc/self/mountinfo writes for \,
// space, tab and newline.
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
