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
// contains_service_name, repetitive and sequential.
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
	if sequential(lower) {
		return &WeakPasswordError{"sequential", "the password is almost all runs such as \"abcdef\", \"12345\", \"qwerty\" or \"aaaa\""}
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

// Neighbours in either direction continue a run; 9 and 0 are neighbours, as
// on the keyboard.
var sequences = []string{"abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"}

const (
	minRun = 3
	// A password needs at least this many characters outside runs, so that
	// "abcdefghijklmno" and "abcdefghijklmno!" are both refused.
	minOutsideRuns = 3
)

// sequential reports whether all but a few characters of s lie in runs of
// at least minRun that repeat a character or step through one of sequences,
// such as "abcdef", "12345", "qwerty", "aaaa" and "abcba".
func sequential(s string) bool {
	r := []rune(s)
	outside, start := 0, 0
	for i := 1; i <= len(r); i++ {
		if i < len(r) && (r[i] == r[i-1] || adjacent(r[i-1], r[i])) {
			continue
		}
		if n := i - start; n < minRun {
			outside += n
		}
		start = i
	}
	return outside < minOutsideRuns
}

func adjacent(a, b rune) bool {
	pair, reversed := string([]rune{a, b}), string([]rune{b, a})
	for _, s := range sequences {
		if strings.Contains(s, pair) || strings.Contains(s, reversed) {
			return true
		}
	}
	return false
}
