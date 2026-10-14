package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeUsername(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		err      error
	}{
		{"alice", "alice", nil},
		{"Alice", "alice", nil},
		{"a.b-c_d9", "a.b-c_d9", nil},
		{"abc", "abc", nil},
		{strings.Repeat("a", 32), strings.Repeat("a", 32), nil},
		{"ab", "", ErrInvalidUsername},
		{strings.Repeat("a", 33), "", ErrInvalidUsername},
		{"bob.", "", ErrInvalidUsername},
		{".bob", "", ErrInvalidUsername},
		{"bo b", "", ErrInvalidUsername},
		{"bob/x", "", ErrInvalidUsername},
		{"Kelvin", "", ErrInvalidUsername},
		{"émile", "", ErrInvalidUsername},
		{"con", "", ErrInvalidUsername},
		{"NUL.a", "", ErrInvalidUsername},
		{"com1.x", "", ErrInvalidUsername},
		{"lpt9", "", ErrInvalidUsername},
		{"com10", "com10", nil},
		{"console", "", ErrUsernameTaken},
		{"System", "", ErrUsernameTaken},
		{"anonymous", "", ErrUsernameTaken},
	} {
		got, err := NormalizeUsername(tc.in)
		if got != tc.want || !errors.Is(err, tc.err) {
			t.Errorf("%q = %q, %v; want %q, %v", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestSetupCode(t *testing.T) {
	code, check := NewSetupCode()
	if len(code) != 26 || strings.ToUpper(code) != code {
		t.Fatalf("code %q", code)
	}
	formatted := FormatCode(code)
	if len(formatted) != 31 || formatted[5] != ' ' {
		t.Errorf("formatted %q", formatted)
	}
	for _, in := range []string{code, strings.ToLower(code), formatted, strings.ReplaceAll(formatted, " ", "-")} {
		if !check.Matches(in) {
			t.Errorf("%q not accepted", in)
		}
	}
	for _, in := range []string{"", code[:25], code + "A", strings.Repeat("A", 26)} {
		if check.Matches(in) {
			t.Errorf("%q accepted", in)
		}
	}
	if other, _ := NewSetupCode(); other == code {
		t.Error("two codes are equal")
	}
}
