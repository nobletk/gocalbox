// Package auth holds the account rules: password hashing and policy,
// usernames, the setup code, and creating the first admin.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id parameters; Memory is in KiB.
type Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
}

// The passes keep one hash well under the 0.5 s a login may take (auth
// design §5.3); every login and every hashing slot pays that time. Memory and
// lanes stay at OWASP's minimum.
var DefaultParams = Params{Memory: 19 * 1024, Time: 32, Threads: 1}

const (
	saltLen = 16
	keyLen  = 32

	maxMemory  = 1 << 22
	maxTime    = 1 << 10
	maxKeyLen  = 64
	minSaltLen = 8

	// A stored hash may cost at most this many times the memory, and the
	// memory times passes, of the hasher's own parameters, so a damaged or
	// planted record cannot make one check take gigabytes or minutes.
	maxMemoryFactor = 4
	maxWorkFactor   = 16
	maxThreads      = 4
)

var (
	ErrBusy          = errors.New("no password-hashing slot became free in time")
	ErrMalformedHash = errors.New("malformed password hash")
)

var b64 = base64.RawStdEncoding

// Hasher hashes and checks passwords, running at most a fixed number of
// Argon2id computations at once; each holds Params.Memory while it runs.
type Hasher struct {
	params Params
	slots  chan struct{}
	wait   time.Duration
}

func NewHasher(p Params, slots int, wait time.Duration) *Hasher {
	return &Hasher{params: p, slots: make(chan struct{}, max(slots, 1)), wait: wait}
}

func (h *Hasher) Params() Params { return h.params }

func (h *Hasher) Hash(ctx context.Context, password string) (string, error) {
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	return hashPassword(h.params, password), nil
}

// Verify reports whether password matches encoded, and whether encoded used
// weaker parameters than the hasher's and should be replaced.
func (h *Hasher) Verify(ctx context.Context, encoded, password string) (ok, rehash bool, err error) {
	ph, err := parsePHC(encoded)
	if err != nil {
		return false, false, err
	}
	if !h.affordable(ph.params) {
		return false, false, fmt.Errorf("%w: parameters beyond the limits (%+v)", ErrMalformedHash, ph.params)
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), ph.salt, ph.params.Time, ph.params.Memory, ph.params.Threads, uint32(len(ph.key)))
	ok = subtle.ConstantTimeCompare(got, ph.key) == 1
	rehash = ph.params.Memory < h.params.Memory || ph.params.Time < h.params.Time ||
		len(ph.salt) < saltLen || len(ph.key) < keyLen
	return ok, rehash, nil
}

// dummy is a hash of no password, checked for unknown usernames so that
// their answer takes as long as a wrong password's.
func (h *Hasher) dummy() string {
	salt, key := make([]byte, saltLen), make([]byte, keyLen)
	rand.Read(salt)
	rand.Read(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Time, h.params.Threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func (h *Hasher) affordable(p Params) bool {
	work := uint64(p.Memory) * uint64(p.Time)
	ownWork := uint64(h.params.Memory) * uint64(h.params.Time)
	return uint64(p.Memory) <= maxMemoryFactor*uint64(h.params.Memory) && work <= maxWorkFactor*ownWork && p.Threads <= maxThreads
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.slots <- struct{}{}:
		return nil
	default:
	}
	t := time.NewTimer(h.wait)
	defer t.Stop()
	select {
	case h.slots <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.slots }

func hashPassword(p Params, password string) string {
	salt := make([]byte, saltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key))
}

type phc struct {
	params    Params
	salt, key []byte
}

func parsePHC(s string) (phc, error) {
	var ph phc
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v="+strconv.Itoa(argon2.Version) {
		return ph, ErrMalformedHash
	}
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if !ok || err != nil || seen[k] {
			return ph, ErrMalformedHash
		}
		seen[k] = true
		switch k {
		case "m":
			ph.params.Memory = uint32(n)
		case "t":
			ph.params.Time = uint32(n)
		case "p":
			if n > 255 {
				return ph, ErrMalformedHash
			}
			ph.params.Threads = uint8(n)
		default:
			return ph, ErrMalformedHash
		}
	}
	p := ph.params
	if len(seen) != 3 || p.Threads == 0 || p.Time == 0 || p.Time > maxTime || p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemory {
		return ph, ErrMalformedHash
	}
	var err error
	if ph.salt, err = b64.DecodeString(parts[4]); err != nil || len(ph.salt) < minSaltLen {
		return ph, ErrMalformedHash
	}
	if ph.key, err = b64.DecodeString(parts[5]); err != nil || len(ph.key) < 16 || len(ph.key) > maxKeyLen {
		return ph, ErrMalformedHash
	}
	return ph, nil
}
