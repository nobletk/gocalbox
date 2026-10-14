package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ctx = context.Background()

// Small parameters keep the tests fast; the format and the checks are the same.
var testParams = Params{Memory: 64, Time: 1, Threads: 1}

func TestHashAndVerify(t *testing.T) {
	h := NewHasher(testParams, 2, time.Second)
	enc, err := h.Hash(ctx, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\$argon2id\$v=19\$m=64,t=1,p=1\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$`).MatchString(enc) {
		t.Fatalf("not a PHC string: %s", enc)
	}
	if again, _ := h.Hash(ctx, "correct horse battery staple"); again == enc {
		t.Error("two hashes of one password are equal; the salt is not random")
	}
	if ok, rehash, err := h.Verify(ctx, enc, "correct horse battery staple"); !ok || rehash || err != nil {
		t.Errorf("right password: %v %v %v", ok, rehash, err)
	}
	if ok, _, err := h.Verify(ctx, enc, "correct horse battery stapl"); ok || err != nil {
		t.Errorf("wrong password: %v %v", ok, err)
	}
}

func TestVerifyAsksForRehashWithStrongerParams(t *testing.T) {
	enc, _ := NewHasher(testParams, 1, time.Second).Hash(ctx, "pw")
	stronger := NewHasher(Params{Memory: 128, Time: 2, Threads: 1}, 1, time.Second)
	if ok, rehash, err := stronger.Verify(ctx, enc, "pw"); !ok || !rehash || err != nil {
		t.Errorf("ok=%v rehash=%v err=%v", ok, rehash, err)
	}
}

func TestDefaultParamsStayAboveOWASPsMinimum(t *testing.T) {
	if p := DefaultParams; p.Memory < 19*1024 || p.Time < 2 || p.Threads != 1 {
		t.Errorf("DefaultParams = %+v, below OWASP's 19 MiB, 2 passes, 1 lane", p)
	}
	enc, _ := NewHasher(DefaultParams, 1, time.Second).Hash(ctx, "pw")
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=19456,t=32,p=1$") {
		t.Errorf("hash = %s", enc)
	}
}

func TestMalformedHashesAreRefused(t *testing.T) {
	good, _ := NewHasher(testParams, 1, time.Second).Hash(ctx, "pw")
	parts := strings.Split(good, "$")
	salt, key := parts[4], parts[5]
	h := NewHasher(testParams, 1, time.Second)
	for _, enc := range []string{
		"",
		"$argon2i$v=19$m=64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=16$m=64,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,x=1$" + salt + "$" + key,
		"$argon2id$v=19$m=4194304,t=1,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1000,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=0,p=1$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=0$" + salt + "$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "=$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$AAAA$" + key,
		"$argon2id$v=19$m=64,t=1,p=1$" + salt + "$AAAA",
		good + "$",
	} {
		if _, _, err := h.Verify(ctx, enc, "pw"); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%q: %v", enc, err)
		}
	}
}

func TestVerifyRefusesHashesFarCostlierThanItsOwn(t *testing.T) {
	h := NewHasher(Params{Memory: 64, Time: 2, Threads: 1}, 1, time.Second)
	for _, p := range []Params{{Memory: 256, Time: 8, Threads: 1}, {Memory: 64, Time: 32, Threads: 4}} {
		enc := hashPassword(p, "pw")
		if ok, _, err := h.Verify(ctx, enc, "pw"); !ok || err != nil {
			t.Errorf("%+v: %v %v", p, ok, err)
		}
	}
	for _, p := range []Params{{Memory: 257, Time: 1, Threads: 1}, {Memory: 128, Time: 17, Threads: 1}, {Memory: 64, Time: 1, Threads: 5}} {
		enc := hashPassword(p, "pw")
		if _, _, err := h.Verify(ctx, enc, "pw"); !errors.Is(err, ErrMalformedHash) {
			t.Errorf("%+v accepted: %v", p, err)
		}
	}
}

func TestHasherLimitsConcurrentHashes(t *testing.T) {
	h := NewHasher(testParams, 1, 50*time.Millisecond)
	h.slots <- struct{}{}
	start := time.Now()
	if _, err := h.Hash(ctx, "pw"); !errors.Is(err, ErrBusy) {
		t.Fatalf("with no free slot: %v", err)
	}
	if d := time.Since(start); d < 40*time.Millisecond {
		t.Errorf("gave up after %v", d)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.Hash(cancelled, "pw"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	h.release()
	if _, err := h.Hash(ctx, "pw"); err != nil {
		t.Errorf("after release: %v", err)
	}
}

// Run on the machine that will serve, to choose the passes:
//
//	go test -run '^$' -bench Argon2id -benchtime 20x ./internal/auth
func BenchmarkArgon2id(b *testing.B) {
	for _, passes := range []uint32{2, 4, 8, 16, 32} {
		p := DefaultParams
		p.Time = passes
		b.Run(fmt.Sprintf("m=%d,t=%d", p.Memory, p.Time), func(b *testing.B) {
			for b.Loop() {
				hashPassword(p, "correct horse battery staple")
			}
		})
	}
}
