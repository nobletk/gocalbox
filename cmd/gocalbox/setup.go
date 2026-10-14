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

	"github.com/nobletk/gocalbox/internal/auth"
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

// logSetup prints the setup code once. The link for another device comes
// only after the steps to trust the local CA: opening it before would show a
// certificate warning, and clicking through that on a hostile network would
// hand over the code.
func (a *app) logSetup(listenHost, port string) {
	code := a.setupCode
	if code == "" {
		return
	}
	a.setupCode = ""
	fragment := "/#setup=" + code
	local, other := setupAddresses(listenHost, port, a.AllowedHosts, a.TLS)

	log.Printf("SETUP: There is no admin account yet. Until there is, every file and API request is answered with 503 setup_required.")
	log.Printf("SETUP: One-time setup code: %s (valid until it is used or the server stops)", auth.FormatCode(code))
	if local != "" {
		log.Printf("SETUP: On this machine, open %s%s", local, fragment)
	}
	switch {
	case a.TLS == nil:
		log.Printf("SETUP: Plain HTTP serves this machine only, so the code works only here.")
	case other == "" && isLoopback(listenHost):
		log.Printf("SETUP: The server listens on loopback only, so other devices cannot reach it.")
	case other == "":
		log.Printf("SETUP: No address for other devices is known; add the machine's LAN address with -allowed-hosts to have one printed here.")
	case a.TLS.CA != nil:
		log.Printf("SETUP: From another device, first install the local CA: open %s and check that the installer shows the fingerprint %s.",
			caURL(listenHost, port, a.AllowedHosts), a.TLS.CA.Fingerprint())
		log.Printf("SETUP: Then open %s%s", other, fragment)
	default:
		log.Printf("SETUP: From another device, open %s%s", other, fragment)
	}

	if lines := setupCommand(runtime.GOOS, local, other, port, a.AllowedHosts, a.TLS, code, a.minPwLen); lines != nil {
		log.Printf("SETUP: The web UI has no setup page yet; until it does, create the admin with")
		for _, l := range lines {
			log.Printf("SETUP: %s", l)
		}
	}
}

// setupCommand has the JSON typed on standard input, so the password stays
// out of the command line and the shell's history.
func setupCommand(goos, local, other, port string, allowed []string, t *tlsSetup, code string, minLen int) []string {
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
	args = append(args, "-H", quote("Content-Type: application/json"), "--data", data, arg(base+"/api/setup"))
	lines := []string{
		"  " + strings.Join(args, " "),
		fmt.Sprintf(`then type {"code":"%s","username":"admin","password":"<at least %d characters>"}, %s.`, code, minLen, end),
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
