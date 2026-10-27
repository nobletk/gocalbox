// Command fakesshd stands in for OpenSSH's sshd in the tests of the
// benchmark scripts. It checks the configuration they write as sshd -t
// would, greets each connection as sshd does, and then works for a while
// in a session process of its own, which it reaps. It tells the fake sftp
// and scp, through the folder $FAKE_SSH_STATE, where it serves and with
// which keys. With FAKE_SSHD_DIP set, each session also has a process work
// whose time is then lost, as a process that ignores SIGCHLD loses its
// children's: the CPU read over the tree falls.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "-dip" {
		dip()
		return
	}
	foreground := flag.Bool("D", false, "")
	stderr := flag.Bool("e", false, "")
	config := flag.String("f", "/etc/ssh/sshd_config", "")
	test := flag.Bool("t", false, "")
	version := flag.Bool("V", false, "")
	flag.Parse()
	if *version {
		fmt.Fprintln(os.Stderr, "OpenSSH_fake, OpenSSL fake")
		return
	}
	if !filepath.IsAbs(os.Args[0]) {
		log.Fatal("sshd re-exec requires execution with an absolute path")
	}
	cfg, err := read(*config)
	if err != nil {
		log.Fatal(err)
	}
	if *test {
		return
	}
	if !*foreground || !*stderr {
		log.Fatal("the scripts run sshd with -D -e")
	}
	state := os.Getenv("FAKE_SSH_STATE")
	l, err := net.Listen("tcp", net.JoinHostPort(cfg["ListenAddress"], cfg["Port"]))
	if err != nil {
		log.Fatal(err)
	}
	pub, _ := os.ReadFile(cfg["HostKey"] + ".pub")
	if err := os.WriteFile(filepath.Join(state, "server"), fmt.Appendf(nil, "%s\n%s\n%s\n%s",
		cfg["Port"], strings.TrimSpace(string(pub)), cfg["AuthorizedKeysFile"], cfg["root"]), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("Server listening on %s port %s.", cfg["ListenAddress"], cfg["Port"])
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Fprint(c, "SSH-2.0-OpenSSH_fake\r\n")
		go func() {
			defer c.Close()
			buf := make([]byte, 1)
			if n, _ := c.Read(buf); n == 0 {
				return
			}
			// A session's work, in a process left behind by the one that started it, as sshd's
			// monitor leaves its session's process.
			f, err := os.CreateTemp("", "fakesshd-")
			if err != nil {
				return
			}
			f.Close()
			os.Remove(f.Name())
			exec.Command("/bin/sh", "-c", `(/bin/sh -c 'i=0; while [ $i -lt 100000 ]; do i=$((i + 1)); done; : > "$0"' "$1" &)`, "sh", f.Name()).Run()
			for {
				if _, err := os.Stat(f.Name()); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			os.Remove(f.Name())
			if os.Getenv("FAKE_SSHD_DIP") != "" {
				exec.Command(os.Args[0], "-dip").Run()
			}
			c.Write([]byte("done\n"))
		}()
	}
}

// dip has a child work for a while and waits for it to end, with SIGCHLD
// ignored, so that the kernel reaps it and its time counts nowhere.
func dip() {
	signal.Ignore(syscall.SIGCHLD)
	pid, err := syscall.ForkExec("/bin/sh", []string{"sh", "-c", "i=0; while [ $i -lt 300000 ]; do i=$((i + 1)); done"},
		&syscall.ProcAttr{Files: []uintptr{0, 1, 2}})
	if err != nil {
		log.Fatal(err)
	}
	for syscall.Kill(pid, 0) == nil {
		time.Sleep(20 * time.Millisecond)
	}
}

// read reads the settings the scripts write, refusing others and missing ones.
func read(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg := map[string]string{}
	want := map[string]string{"AuthenticationMethods": "publickey", "PasswordAuthentication": "no", "UsePAM": "no",
		"Subsystem": "sftp internal-sftp", "DisableForwarding": "yes", "PermitTTY": "no"}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), " ")
		if strings.HasPrefix(v, `"`) {
			v = strings.Trim(v, `"`)
		}
		cfg[k] = v
	}
	for k, v := range want {
		if cfg[k] != v {
			return nil, fmt.Errorf("%s: %s is %q, not %q", path, k, cfg[k], v)
		}
	}
	root, ok := strings.CutPrefix(cfg["ForceCommand"], "internal-sftp -d ")
	if !ok {
		return nil, errors.New(path + ": no ForceCommand internal-sftp -d")
	}
	cfg["root"] = strings.Trim(root, `"`)
	for _, k := range []string{"Port", "ListenAddress", "HostKey", "AuthorizedKeysFile", "AllowUsers", "PidFile"} {
		if cfg[k] == "" {
			return nil, fmt.Errorf("%s: no %s", path, k)
		}
	}
	return cfg, nil
}
