package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestPolicy(t *testing.T) {
	p := Policy{MinLength: 15}
	for _, tc := range []struct {
		username, password, reason string
	}{
		{"alice", "plenty of length here", ""},
		{"alice", "ünïcødé çhàrs ok", ""},
		{"alice", "short one", "too_short"},
		{"alice", strings.Repeat("ü", 14), "too_short"},
		{"alice", strings.Repeat("ab1", 342) + "x", "too_long"},
		{"alice", "films+pic+galeries", "common"},
		{"alice", "FILMS+PIC+GALERIES", "common"},
		{"alice", "my name is Alice, hello there", "contains_username"},
		{"bob", "I love GoCalBox so very much", "contains_service_name"},
		{"bob", "passwordpassword", "repetitive"},
		{"bob", "aaaaaaaaaaaaaaaaaaaa", "repetitive"},
		{"bob", "xyzxyzxyzxyzxyzxy", "repetitive"},
		{"bob", "kqmkqmkqmkqmkqmkr", ""},
		{"bob", "abcdefghijklmno", "sequential"},
		{"bob", "ABCDEFGHIJKLMNO!", "sequential"},
		{"bob", "onmlkjihgfedcba", "sequential"},
		{"bob", "123456789012345", "sequential"},
		{"bob", "0987654321098765", "sequential"},
		{"bob", "qwertyuiopasdfghjkl", "sequential"},
		{"bob", "abcdef123456789", "sequential"},
		{"bob", "aaabbbcccdddeee", "sequential"},
		{"bob", "xyzxyzxyzxyzxyzxq", "sequential"},
		{"bob", "abcdefghijkl!x9", ""},
		{"bob", "correct horse battery staple", ""},
		{"bob", "my abc puzzle is fun to solve", ""},
		{"bob", "tH7#qz!pL4mW8vRk", ""},
		{"bob", "caf\xe9 au lait, s'il vous plait", "not_utf8"},
		{"bob", strings.Repeat("\xff", 15), "not_utf8"},
	} {
		err := p.Check(tc.username, tc.password)
		var we *WeakPasswordError
		switch {
		case tc.reason == "" && err != nil:
			t.Errorf("%q refused: %v", tc.password, err)
		case tc.reason != "" && (!errors.As(err, &we) || we.Reason != tc.reason):
			t.Errorf("%q: %v, want reason %s", tc.password, err, tc.reason)
		}
	}
}

func TestPolicyLowerMinimumUsesTheBlocklist(t *testing.T) {
	p := Policy{MinLength: 8}
	var we *WeakPasswordError
	if err := p.Check("alice", "12345678"); !errors.As(err, &we) || we.Reason != "common" {
		t.Errorf("12345678: %v", err)
	}
	if err := p.Check("alice", "tH7#qz!pL"); err != nil {
		t.Errorf("uncommon 9-character password: %v", err)
	}
	if err := p.Check("alice", "lmnopqr7"); !errors.As(err, &we) || we.Reason != "sequential" {
		t.Errorf("lmnopqr7: %v", err)
	}
}

func TestBlocklistIsLoaded(t *testing.T) {
	set := commonPasswords()
	if len(set) < 9990 {
		t.Fatalf("%d entries", len(set))
	}
	for _, pw := range []string{"password", "123456", "qwerty"} {
		if _, ok := set[pw]; !ok {
			t.Errorf("%q missing", pw)
		}
	}
}
