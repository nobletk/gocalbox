package auth

import (
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/nobletk/gocalbox/internal/events"
	"github.com/nobletk/gocalbox/internal/state"
)

var (
	ErrInvalidUsername = errors.New("invalid username")
	ErrUsernameTaken   = state.ErrUsernameTaken
)

// Usernames become folder names; a trailing dot is refused because Windows
// drops it, so "bob." would name Bob's folder.
var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,30}[a-z0-9]$`)

var windowsDevices = []string{
	"con", "prn", "aux", "nul",
	"com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
	"lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}

var reservedNames = []string{events.AnonymousID, events.ConsoleID, events.SystemID}

// NormalizeUsername lowercases ASCII letters and checks the result. Only
// ASCII is lowered: Unicode case mapping would turn the Kelvin sign into "k".
func NormalizeUsername(s string) (string, error) {
	name := strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
	if !usernamePattern.MatchString(name) {
		return "", ErrInvalidUsername
	}
	// Windows treats "nul.txt" as the device too.
	device, _, _ := strings.Cut(name, ".")
	if slices.Contains(windowsDevices, device) {
		return "", ErrInvalidUsername
	}
	if slices.Contains(reservedNames, name) {
		return "", ErrUsernameTaken
	}
	return name, nil
}

// HomeOf is the home folder of a username, relative to the served root.
func HomeOf(username string) string { return "users/" + username }
