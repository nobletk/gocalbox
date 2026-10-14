package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/state"
)

// DeviceCookieLifetime is the longest a cookie may live in Chromium.
const DeviceCookieLifetime = 400 * 24 * time.Hour

// The device cookie marks a browser where an account has logged in. It
// serves only the throttle and grants no access. The account's epoch is in
// the MAC, so a new password makes every other browser's cookie invalid.
func deviceMAC(key []byte, userID string, issued int64, epoch uint64) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(userID + "\x00" + strconv.FormatInt(issued, 10) + "\x00" + strconv.FormatUint(epoch, 10)))
	return m.Sum(nil)
}

func (a *Accounts) deviceCookie(u state.User) string {
	issued := a.now().Unix()
	return u.ID + "." + strconv.FormatInt(issued, 10) + "." + base64.RawURLEncoding.EncodeToString(deviceMAC(a.deviceKey, u.ID, issued, u.Epoch))
}

func (a *Accounts) trustedDevice(cookie string, u state.User) bool {
	id, rest, ok := strings.Cut(cookie, ".")
	if !ok || id != u.ID {
		return false
	}
	issuedText, macText, ok := strings.Cut(rest, ".")
	if !ok {
		return false
	}
	issued, err := strconv.ParseInt(issuedText, 10, 64)
	if err != nil {
		return false
	}
	mac, err := base64.RawURLEncoding.DecodeString(macText)
	if err != nil || !hmac.Equal(mac, deviceMAC(a.deviceKey, u.ID, issued, u.Epoch)) {
		return false
	}
	age := a.now().Sub(time.Unix(issued, 0))
	return age < DeviceCookieLifetime && age > -time.Hour
}
