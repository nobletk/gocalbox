package auth

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	throttleEntries = 10000
	freeFailures    = 5
	firstBackoff    = time.Second
	maxBackoff      = 15 * time.Minute

	// Clients without the account's device cookie are refused from this many
	// consecutive failures of the account on; at disableAt the password is
	// disabled (NIST SP 800-63B-4 §3.2.2 allows at most 100).
	untrustedLimit = 50
	disableAt      = 100

	ownNetworksTTL = time.Minute
)

func defaultFailureDelay(n int) time.Duration {
	return min(time.Duration(n)*100*time.Millisecond, 5*time.Second)
}

// throttle counts consecutive failures. Addresses, (username, address)
// pairs and unknown usernames share the most recently used throttleEntries
// counters. Known accounts' counters are kept apart and never dropped, so
// filling the shared ones cannot reset an account's count.
type throttle struct {
	now func() time.Time

	mu       sync.Mutex
	order    *list.List
	entries  map[string]*list.Element
	accounts map[string]*counter // by user ID

	netsMu    sync.Mutex
	nets      []netip.Prefix
	netsAt    time.Time
	ownPrefix func() []netip.Prefix
}

type counter struct {
	key      string
	failures int
	last     time.Time
}

// account names the per-account counter of a login attempt.
type account struct {
	key      string // user ID if known, else the typed username
	known    bool
	stored   int  // the count the state file holds
	disabled bool // the state file says the password is disabled
}

func newThrottle(now func() time.Time, ownPrefix func() []netip.Prefix) *throttle {
	if ownPrefix == nil {
		ownPrefix = interfacePrefixes
	}
	return &throttle{now: now, order: list.New(), entries: map[string]*list.Element{}, accounts: map[string]*counter{}, ownPrefix: ownPrefix}
}

// peek returns the counter of key, or nil, without creating it: a refused
// attempt must not add counters, or it could push others out.
func (t *throttle) peek(key string) *counter {
	if e, ok := t.entries[key]; ok {
		return e.Value.(*counter)
	}
	return nil
}

func (t *throttle) get(key string) *counter {
	if e, ok := t.entries[key]; ok {
		t.order.MoveToFront(e)
		return e.Value.(*counter)
	}
	c := &counter{key: key}
	t.entries[key] = t.order.PushFront(c)
	for t.order.Len() > throttleEntries {
		old := t.order.Back()
		t.order.Remove(old)
		delete(t.entries, old.Value.(*counter).key)
	}
	return c
}

func (t *throttle) account(a account, create bool) *counter {
	if !a.known {
		if create {
			return t.get(userKey(a.key))
		}
		return t.peek(userKey(a.key))
	}
	c, ok := t.accounts[a.key]
	if !ok {
		c = &counter{key: a.key, failures: a.stored}
		if create {
			t.accounts[a.key] = c
		}
	}
	return c
}

// backoff returns how long the hard back-off still refuses c.
func (t *throttle) backoff(c *counter) time.Duration {
	if c == nil || c.failures < freeFailures {
		return 0
	}
	backoff := maxBackoff
	if shift := c.failures - freeFailures; shift < 10 {
		backoff = min(firstBackoff<<shift, maxBackoff)
	}
	return max(c.last.Add(backoff).Sub(t.now()), 0)
}

// admitted holds the counters of the address, the pair and the account that
// an attempt was counted under.
type admitted [3]*counter

// admit decides whether a password may be checked. If so, it counts the
// attempt as a failure of the address, the pair and the account before the
// check, so that attempts arriving together cannot all pass one limit; a
// success then resets the counters. It returns the account's count with
// this attempt, and the counters it counted under.
func (t *throttle) admit(addr, pair string, a account, untrusted bool) (int, admitted, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if wait := max(t.backoff(t.peek(addr)), t.backoff(t.peek(pair))); wait > 0 {
		return 0, admitted{}, &TooManyAttemptsError{RetryAfter: wait}
	}
	n := 0
	if c := t.account(a, false); c != nil {
		n = c.failures
	}
	if a.known && a.disabled {
		return 0, admitted{}, ErrPasswordDisabled
	}
	// The count can reach disableAt with the last attempt still being
	// checked; that attempt decides whether the password is disabled.
	if a.known && n >= disableAt {
		return 0, admitted{}, &TooManyAttemptsError{RetryAfter: firstBackoff}
	}
	if untrusted && n >= untrustedLimit {
		return 0, admitted{}, &TooManyAttemptsError{}
	}
	now := t.now()
	got := admitted{t.get(addr), t.get(pair), t.account(a, true)}
	for _, c := range got {
		c.failures++
		c.last = now
	}
	return n + 1, got, nil
}

// current reports whether c is still the counter of a known account, that
// is, no success or new password has reset the count since c was admitted.
func (t *throttle) current(a account, c *counter) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return a.known && t.accounts[a.key] == c
}

// giveBack undoes admit's count for an attempt whose password was never
// checked. A counter that a success has replaced since is left alone, so the
// failures of other attempts counted on its successor stay.
func (t *throttle) giveBack(addr, pair string, a account, got admitted) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for i, c := range []*counter{t.peek(addr), t.peek(pair), t.account(a, false)} {
		if c != nil && c == got[i] && c.failures > 0 {
			c.failures--
		}
	}
}

// succeed resets the counters of an attempt with the right password. A known
// account gets a new counter at 0 rather than none, which would start again
// from the stored count before the success has reset it.
func (t *throttle) succeed(addr, pair string, a account) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drop(addr, pair)
	if a.known {
		t.accounts[a.key] = &counter{key: a.key}
	} else {
		t.drop(userKey(a.key))
	}
}

// resetAccount clears a known account's count, as a new password does. Like
// succeed, it leaves a counter at 0.
func (t *throttle) resetAccount(userID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.accounts[userID] = &counter{key: userID}
}

// wait returns how long the back-off still refuses key; fail counts a
// failure of it, and reset clears it. They serve the counter for setup codes
// and link tokens, whose checks take no hashing time.
func (t *throttle) wait(key string) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.backoff(t.peek(key))
}

func (t *throttle) fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.get(key)
	c.failures++
	c.last = t.now()
}

func (t *throttle) reset(keys ...string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.drop(keys...)
}

func (t *throttle) drop(keys ...string) {
	for _, k := range keys {
		if e, ok := t.entries[k]; ok {
			t.order.Remove(e)
			delete(t.entries, k)
		}
	}
}

func addressKey(addr string) string    { return "a\x00" + addr }
func pairKey(name, addr string) string { return "p\x00" + name + "\x00" + addr }
func userKey(name string) string       { return "u\x00" + name }
func codeKey(addr string) string       { return "c\x00" + addr }

// group returns the address that counts for remoteAddr. An IPv6 address on
// one of the server's own networks counts alone, since every device of a
// home network shares its /64; any other IPv6 address counts as its /64,
// which one attacker usually holds whole.
func (t *throttle) group(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	ip = ip.Unmap().WithZone("")
	if ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || t.ownNetwork(ip) {
		return ip.String()
	}
	p, _ := ip.Prefix(64)
	return p.String()
}

func (t *throttle) ownNetwork(ip netip.Addr) bool {
	t.netsMu.Lock()
	defer t.netsMu.Unlock()
	if now := t.now(); t.nets == nil || now.Sub(t.netsAt) >= ownNetworksTTL || now.Before(t.netsAt) {
		t.nets, t.netsAt = t.ownPrefix(), now
	}
	for _, p := range t.nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func interfacePrefixes() []netip.Prefix {
	out := []netip.Prefix{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok || !ip.Unmap().Is6() {
			continue
		}
		if p, err := ip.Unmap().Prefix(64); err == nil {
			out = append(out, p)
		}
	}
	return out
}
