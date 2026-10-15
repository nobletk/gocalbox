package main

import (
	"cmp"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/internal/auth"
	"github.com/nobletk/gocalbox/internal/httpapi"
	"github.com/nobletk/gocalbox/internal/sandbox"
)

// prepareStateFile resolves the state file's path, creating its folder, and
// refuses it inside the served directory, where clients could download it.
func prepareStateFile(root, path string) (string, error) {
	if path == "" {
		return "", errors.New("-state is empty; give the path of the state file")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err := refuseInsideRoot(root, abs, "-state"); err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return "", fmt.Errorf("create the folder of -state: %w", err)
	}
	dir, err := outsideRoot(root, filepath.Dir(abs), "-state")
	if err != nil {
		return "", err
	}
	resolved := filepath.Join(dir, filepath.Base(abs))
	if _, err := os.Lstat(resolved); err == nil {
		return outsideRoot(root, resolved, "-state")
	}
	return resolved, nil
}

// refuseInsideRoot checks a path before its missing folders are created, so
// a refused start leaves nothing in the served directory.
func refuseInsideRoot(root, abs, flagName string) error {
	resolved, err := sandbox.ResolveExisting(abs)
	if err != nil {
		return fmt.Errorf("%s: %w", flagName, err)
	}
	if sandbox.Within(root, abs) || sandbox.Within(root, resolved) {
		return insideRootError(flagName, resolved, root)
	}
	return nil
}

// logSetup prints the setup code once.
func (a *app) logSetup(listenHost, port string) {
	code := a.setupCode
	if code == "" {
		return
	}
	a.setupCode = ""
	log.Printf("SETUP: There is no admin account yet. Until there is, files and the API answer 503 setup_required, except setup, status, login, links and the session routes.")
	log.Printf("SETUP: One-time setup code: %s (valid until it is used or the server stops)", auth.FormatCode(code))
	local, other := a.logLink("SETUP", "/#setup="+code, "code", listenHost, port)
	if lines := setupCommand(runtime.GOOS, local, other, port, a.AllowedHosts, a.TLS, code, a.minPwLen); lines != nil {
		log.Printf("SETUP: The web UI has no setup page yet; until it does, create the admin with")
		for _, l := range lines {
			log.Printf("SETUP: %s", l)
		}
	}
}

// logRecovery prints the reset link of -recover-admin once.
func (a *app) logRecovery(listenHost, port string) {
	l := a.recovery
	if l.Token == "" {
		return
	}
	a.recovery = auth.NewLink{}
	log.Printf("RECOVERY: Reset link for the admin %s, for one use until %s. Use it at once: console output may be kept, such as in a service's journal.",
		l.Username, l.Expires.Local().Format(time.DateTime))
	local, other := a.logLink("RECOVERY", "/#reset="+l.Token, "link", listenHost, port)
	body := fmt.Sprintf(`{"token":"%s","password":"<at least %d characters>"}`, l.Token, a.minPwLen)
	if lines := apiCommand(runtime.GOOS, local, other, port, a.AllowedHosts, a.TLS, "/api/reset/accept", body); lines != nil {
		log.Printf("RECOVERY: The web UI has no reset page yet; until it does, set the new password with")
		for _, l := range lines {
			log.Printf("RECOVERY: %s", l)
		}
	}
}

// logLink prints where to open a link printed on the console, and returns
// the base addresses it used. The form for another device comes only after
// the steps to trust the local CA: opening it before would show a
// certificate warning, and clicking through that on a hostile network would
// hand over the link's secret.
func (a *app) logLink(tag, fragment, what, listenHost, port string) (local, other string) {
	local, other = setupAddresses(listenHost, port, a.AllowedHosts, a.TLS)
	if local != "" {
		log.Printf("%s: On this machine, open %s%s", tag, local, fragment)
	}
	switch {
	case a.TLS == nil:
		log.Printf("%s: Plain HTTP serves this machine only, so the %s works only here.", tag, what)
	case other == "" && isLoopback(listenHost):
		log.Printf("%s: The server listens on loopback only, so other devices cannot reach it.", tag)
	case other == "":
		log.Printf("%s: No address for other devices is known; add the machine's LAN address with -allowed-hosts to have one printed here.", tag)
	case a.TLS.CA != nil:
		log.Printf("%s: From another device, first install the local CA: open %s and check that the installer shows the fingerprint %s.",
			tag, caURL(listenHost, port, a.AllowedHosts), a.TLS.CA.Fingerprint())
		log.Printf("%s: Then open %s%s", tag, other, fragment)
	default:
		log.Printf("%s: From another device, open %s%s", tag, other, fragment)
	}
	return local, other
}

// linkTarget is what a new link from the admin page needs: the address
// other devices use, as the console gives for /ca.crt, and the local CA's
// fingerprint.
func (a *app) linkTarget(listenHost, port string) httpapi.LinkTarget {
	_, other := setupAddresses(listenHost, port, a.AllowedHosts, a.TLS)
	t := httpapi.LinkTarget{Address: other}
	if a.TLS != nil && a.TLS.CA != nil {
		t.CAFingerprint = a.TLS.CA.Fingerprint()
	}
	return t
}

// setupCommand has the JSON typed on standard input, so the password stays
// out of the command line and the shell's history.
func setupCommand(goos, local, other, port string, allowed []string, t *tlsSetup, code string, minLen int) []string {
	body := fmt.Sprintf(`{"code":"%s","username":"admin","password":"<at least %d characters>"}`, code, minLen)
	return apiCommand(goos, local, other, port, allowed, t, "/api/setup", body)
}

// apiCommand is a curl command that posts body, typed on standard input,
// to apiPath.
func apiCommand(goos, local, other, port string, allowed []string, t *tlsSetup, apiPath, body string) []string {
	base := cmp.Or(local, other)
	if base == "" {
		return nil
	}
	// cmd.exe takes only double quotes, Windows paths cannot contain one, and
	// PowerShell reads an unquoted @ as splatting. In Windows PowerShell 5.1
	// "curl" is Invoke-WebRequest, so curl.exe is named in full. Its Schannel
	// refuses a certificate whose revocation it cannot check, and a private
	// CA publishes no revocation list.
	quote, curl, data, end, cacert := posixQuote, "curl", "@-", "press Enter, then Ctrl-D", []string{"--cacert"}
	if goos == "windows" {
		quote = func(s string) string { return `"` + s + `"` }
		curl, data, end, cacert = "curl.exe", `"@-"`, "press Enter, then Ctrl-Z and Enter", []string{"--ssl-no-revoke", "--cacert"}
	}
	// zsh, the default shell on macOS, treats an unquoted [ as a pattern.
	arg := func(s string) string {
		if strings.ContainsAny(s, "[]") {
			return quote(s)
		}
		return s
	}
	args := []string{curl}
	var note string
	switch {
	case t == nil:
	case t.CA != nil:
		args = append(append(args, cacert...), quote(t.CAPath))
	default:
		note = "If this machine does not trust the certificate's CA, also give curl " + strings.Join(cacert, " ") + " with the CA's file."
		// A certificate from -tls-cert rarely names localhost. --connect-to
		// keeps the request on this machine while curl checks a name the
		// certificate has.
		if base != local || t.leaf().VerifyHostname("localhost") == nil {
			break
		}
		name := certName(allowed, t.leaf())
		if name == "" {
			note = "The certificate names neither localhost nor any -allowed-hosts name, so this command fails; add a name it has to -allowed-hosts."
			break
		}
		args = append(args, "--connect-to", arg(net.JoinHostPort(name, port)+":"+net.JoinHostPort("localhost", port)))
		base = "https://" + net.JoinHostPort(name, port)
	}
	args = append(args, "-H", quote("Content-Type: application/json"), "--data", data, arg(base+apiPath))
	lines := []string{
		"  " + strings.Join(args, " "),
		fmt.Sprintf(`then type %s, %s.`, body, end),
	}
	if note != "" {
		lines = append(lines, note)
	}
	return lines
}

// posixQuote quotes s for a POSIX shell, where single quotes stop every
// expansion, $ and backquotes included.
func posixQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func certName(allowed []string, leaf *x509.Certificate) string {
	for _, h := range allowed {
		if !isLoopback(h) && leaf.VerifyHostname(h) == nil {
			return h
		}
	}
	return ""
}

// setupAddresses returns the base URL for a browser on the server's own
// machine, if the server accepts loopback connections, and for other
// devices, if one is known.
func setupAddresses(listenHost, port string, allowed []string, t *tlsSetup) (local, other string) {
	scheme := "https"
	if t == nil {
		scheme = "http"
	}
	if acceptsLoopback(listenHost) {
		local = scheme + "://" + net.JoinHostPort("localhost", port)
	}
	switch {
	case t == nil:
	case t.CA != nil:
		if h := lanHost(listenHost, allowed); h != "localhost" {
			other = "https://" + net.JoinHostPort(h, port)
		}
	case isLoopback(listenHost):
	default:
		if name := certName(allowed, t.leaf()); name != "" {
			other = "https://" + net.JoinHostPort(name, port)
		}
	}
	return local, other
}

func acceptsLoopback(listenHost string) bool {
	if listenHost == "" || isLoopback(listenHost) {
		return true
	}
	ip := net.ParseIP(strings.Trim(listenHost, "[]"))
	return ip != nil && ip.IsUnspecified()
}
