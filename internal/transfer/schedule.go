package transfer

import (
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
)

const (
	minPartSize = 8 << 20
	maxPartSize = 64 << 20
	partsTarget = 10000
)

// MaxSize is the largest file a session may declare: 64 TiB, four times the
// largest file ext4 holds, in at most 1,048,576 parts. It keeps the part
// arithmetic far from overflowing and bounds what a session's bookkeeping
// can grow to.
const MaxSize = 1 << 46

// PartSize returns the part size the server uses for a file of size bytes,
// at most MaxSize.
func PartSize(size int64) int64 {
	if size <= 0 {
		return minPartSize
	}
	per := (size + partsTarget - 1) / partsTarget
	p := int64(1) << (64 - bits.LeadingZeros64(uint64(per-1)))
	return min(max(p, minPartSize), maxPartSize)
}

// PartCount returns how many parts of partSize make up size bytes, at most
// MaxSize.
func PartCount(size, partSize int64) int {
	if size <= 0 {
		return 0
	}
	return int((size + partSize - 1) / partSize)
}

// partLen returns the length of part n, numbered from 1.
func partLen(size, partSize int64, n int) int64 {
	off := int64(n-1) * partSize
	return min(partSize, size-off)
}

// Composite returns the hex SHA-256 of the part hashes in order, the hash
// that identifies an upload as a whole. It is not the file's SHA-256.
func Composite(parts [][sha256.Size]byte) string {
	h := sha256.New()
	for i := range parts {
		h.Write(parts[i][:])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Range is an inclusive range of part numbers.
type Range [2]int

func countRanges(rs []Range) int {
	n := 0
	for _, r := range rs {
		n += r[1] - r[0] + 1
	}
	return n
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ValidID reports whether id has the form of an upload ID: 32 lowercase hex
// characters. An ID names a folder, so nothing else may be used as one.
func ValidID(id string) bool { return isHex(id, 32) }

func validClientKey(k string) bool {
	if len(k) > 128 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return false
		}
	}
	return true
}
