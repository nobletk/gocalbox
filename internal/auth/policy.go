package auth

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	DefaultMinPasswordLength = 15
	LowestMinPasswordLength  = 8
	MaxPasswordBytes         = 1024
	serviceName              = "gocalbox"
)

//go:embed common-passwords.txt
var commonPasswordsFile string

var commonPasswords = sync.OnceValue(func() map[string]struct{} {
	set := make(map[string]struct{}, 10000)
	for line := range strings.Lines(commonPasswordsFile) {
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			set[strings.ToLower(line)] = struct{}{}
		}
	}
	return set
})

// WeakPasswordError says why the policy refused a password. Reason is one
// of too_long, not_utf8, too_short, common, contains_username,
// contains_service_name and repetitive.
type WeakPasswordError struct {
	Reason  string
	Message string
}

func (e *WeakPasswordError) Error() string { return "weak password: " + e.Message }

// Policy is the password policy of NIST SP 800-63B-4 for a password that is
// the only factor: a minimum length, a blocklist, and no composition rules.
type Policy struct {
	MinLength int // in characters
}

func (p Policy) Check(username, password string) error {
	if len(password) > MaxPasswordBytes {
		return &WeakPasswordError{"too_long", fmt.Sprintf("the password is longer than %d bytes", MaxPasswordBytes)}
	}
	// Browsers send passwords as UTF-8 in JSON; one hashed from other bytes
	// could never be typed in at login.
	if !utf8.ValidString(password) {
		return &WeakPasswordError{"not_utf8", "the password is not valid UTF-8 text"}
	}
	if n := utf8.RuneCountInString(password); n < p.MinLength {
		return &WeakPasswordError{"too_short", fmt.Sprintf("the password needs at least %d characters, not %d", p.MinLength, n)}
	}
	lower := strings.ToLower(password)
	if _, ok := commonPasswords()[lower]; ok {
		return &WeakPasswordError{"common", "the password is one of the 10,000 most common passwords"}
	}
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return &WeakPasswordError{"contains_username", "the password contains the username"}
	}
	if strings.Contains(lower, serviceName) {
		return &WeakPasswordError{"contains_service_name", "the password contains \"" + serviceName + "\""}
	}
	if repetitive(lower) {
		return &WeakPasswordError{"repetitive", "the password repeats one short sequence, such as \"abcabcabc\""}
	}
	return nil
}

// repetitive reports whether s is a sequence of at most half its length
// repeated, the last copy possibly cut short: "aaaa", "passwordpassword",
// "1231231".
func repetitive(s string) bool {
	r := []rune(s)
	for unit := 1; unit <= len(r)/2; unit++ {
		match := true
		for i := unit; i < len(r); i++ {
			if r[i] != r[i-unit] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
