package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"strings"
)

// SetupCode checks the one-time setup code; only its SHA-256 is kept.
type SetupCode struct {
	sum [sha256.Size]byte
}

// NewSetupCode returns a new code of 130 random bits in base32, to be shown
// once, and its check.
func NewSetupCode() (string, *SetupCode) {
	code := rand.Text()
	return code, &SetupCode{sum: sha256.Sum256([]byte(code))}
}

// Matches ignores case, spaces and dashes, so the code can be typed as
// FormatCode prints it.
func (c *SetupCode) Matches(input string) bool {
	norm := strings.ToUpper(strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' {
			return -1
		}
		return r
	}, input))
	sum := sha256.Sum256([]byte(norm))
	return subtle.ConstantTimeCompare(sum[:], c.sum[:]) == 1
}

func FormatCode(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%5 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
