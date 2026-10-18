// Command gocalbox-load measures resumable uploads: simulated users each
// upload files as the browser does, and every repetition adds a line to a
// CSV file with the columns of the benchmark scripts.
//
// By default the engine runs in this process with the real file operations,
// state file and audit log, but without HTTP and logins. With -url the users
// upload to a running server over HTTPS instead, each logged in over a
// connection of its own: the users <prefix>00, <prefix>01, … must exist,
// made with gocalbox users add as contributors with the one password this
// command reads from standard input. What they uploaded is deleted after
// each repetition. The CSV names the commit of this tree, which should
// then be the server's. Run it from the repository root.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/bench/load"
)

func main() {
	err := run(os.Args[1:], os.Stdin)
	switch {
	case errors.Is(err, flag.ErrHelp):
	case errors.Is(err, errUsage):
		os.Exit(2)
	case err != nil:
		log.Fatal(err)
	}
}

// errUsage is a command line the flag package refused, and has already
// said why.
var errUsage = errors.New("usage")

func run(args []string, stdin io.Reader) error {
	fl := flag.NewFlagSet("gocalbox-load", flag.ContinueOnError)
	work := fl.String("work", filepath.Join("bench", ".work", "load"), "Scratch folder; it must be on the disk being measured, and is emptied before each repetition (in-process only)")
	users := fl.Int("users", 1, "Simulated users uploading at once")
	files := fl.Int("files", 1, "Files each user uploads")
	size := fl.String("size", "64M", "Size of each file, in bytes or with K, M or G (IEC units)")
	parallel := fl.Int("parallel", 4, "Parts each user sends at once, across their files")
	reps := fl.Int("reps", 3, "Repetitions")
	auditWait := fl.Bool("audit-wait", true, "Completions answer only once their audit records are on disk, as the server does by default (in-process only)")
	auditParts := fl.Bool("audit-parts", false, "Record every accepted part in the audit log (in-process only)")
	minFreeMB := fl.Int64("min-free-mb", 1024, "Free space in MiB uploads must leave on the disk (in-process only)")
	csvPath := fl.String("csv", "", "CSV file to append to (default bench/results/<commit>-<time>-load.csv)")
	url := fl.String("url", "", "Upload to the server at this address over HTTPS, such as https://192.168.1.10:8443, rather than in this process")
	ca := fl.String("ca", "", "With -url: the server's CA certificate, ca.crt in its -tls-dir; by default the system's are trusted")
	transport := fl.String("transport", "https-h2", "With -url: https-h2 (HTTP/2, as browsers use it) or https-h1 (HTTP/1.1)")
	userPrefix := fl.String("user-prefix", "load", "With -url: the users are this followed by 00, 01, …")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}

	bytes, err := parseSize(*size)
	if err != nil || *users < 1 || *files < 1 || *parallel < 1 || *reps < 1 {
		return fmt.Errorf("invalid flags: size %q (%v); users, files, parallel and reps must be at least 1", *size, err)
	}
	set := map[string]bool{}
	fl.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := checkModes(set, *url != "", *transport); err != nil {
		return err
	}
	var remote []load.User
	if *url != "" {
		r := load.Remote{URL: *url, HTTP1: *transport == "https-h1"}
		if *ca != "" {
			if r.CA, err = os.ReadFile(*ca); err != nil {
				return err
			}
		}
		password, err := readPassword(stdin)
		if err != nil {
			return err
		}
		if remote, err = load.LogIn(context.Background(), r, userNames(*userPrefix, *users), password); err != nil {
			return err
		}
	}
	commit, dirty := gitState()
	if *csvPath == "" {
		*csvPath = filepath.Join("bench", "results", fmt.Sprintf("%s-%s-load.csv", commit, time.Now().Format("20060102-150405")))
	}
	if err := os.MkdirAll(filepath.Dir(*csvPath), 0o755); err != nil {
		return err
	}
	_, statErr := os.Stat(*csvPath)
	out, err := os.OpenFile(*csvPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if os.IsNotExist(statErr) {
		fmt.Fprintln(out, load.Header)
	}

	scenario := fmt.Sprintf("engine_upload_%du", *users)
	if *auditParts {
		scenario += "_audit_parts"
	}
	if !*auditWait {
		scenario += "_no_wait"
	}
	for rep := 1; rep <= *reps; rep++ {
		var res load.Result
		var server string
		column := "inprocess"
		if remote != nil {
			column = *transport
			res = load.Run(context.Background(), load.Config{Users: remote, Files: *files, Size: bytes, Parallel: *parallel})
		} else {
			if err := emptyWork(*work); err != nil {
				return err
			}
			stack, err := load.NewStack(load.StackOptions{Work: *work, Users: *users, AuditWait: *auditWait,
				AuditParts: *auditParts, MinFree: *minFreeMB << 20})
			if err != nil {
				return err
			}
			res = load.Run(context.Background(), load.Config{Users: stack.Users, Files: *files, Size: bytes, Parallel: *parallel})
			st := stack.Engine.Stats()
			server = fmt.Sprintf("; the engine: %d parts, %d duplicates, refused busy %d, too_many_requests %d, too_many_uploads %d",
				st.PartsReceived, st.Duplicates, st.Busy, st.TooManyRequests, st.TooManyUploads)
			if err := stack.Close(); err != nil {
				log.Printf("closing the stack: %v", err)
			}
		}
		fmt.Fprintln(out, res.Row(commit, dirty, scenario, bytes, *users**parallel, rep, column))
		log.Printf("rep %d: %d of %d files uploaded in %.2fs, %.1f MiB/s, parts p50 %v p99 %v, %s, tried again %s%s",
			rep, res.Uploaded(), res.Files, res.Duration.Seconds(), float64(res.Bytes)/(1<<20)/res.Duration.Seconds(),
			res.Percentile(0.5).Round(time.Microsecond), res.Percentile(0.99).Round(time.Microsecond), res.CodeColumn(),
			counts(res.Retried), server)
		if remote != nil {
			if err := load.Clean(context.Background(), remote); err != nil {
				return fmt.Errorf("removing what rep %d uploaded: %w", rep, err)
			}
		}
	}
	if remote == nil {
		if err := emptyWork(*work); err != nil {
			log.Printf("cannot empty %s: %v", *work, err)
		}
	}
	log.Printf("results: %s", *csvPath)
	return nil
}

// checkModes refuses the flags of the mode not chosen, which would go
// unused without a word.
func checkModes(set map[string]bool, remote bool, transport string) error {
	other, mode := []string{"work", "audit-wait", "audit-parts", "min-free-mb"}, "the in-process mode; set them on the server"
	if !remote {
		other, mode = []string{"ca", "transport", "user-prefix"}, "-url"
	}
	var named []string
	for _, f := range other {
		if set[f] {
			named = append(named, "-"+f)
		}
	}
	if len(named) > 0 {
		return fmt.Errorf("%s: only for %s", strings.Join(named, ", "), mode)
	}
	if transport != "https-h2" && transport != "https-h1" {
		return fmt.Errorf("-transport must be https-h2 or https-h1, not %q", transport)
	}
	return nil
}

// readPassword reads the users' password from the first line of r.
func readPassword(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", errors.New("no password on standard input: give the load users' password there")
	}
	return pw, nil
}

func userNames(prefix string, n int) []string {
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("%s%02d", prefix, i)
	}
	return names
}

// counts lists a count of each status, such as "429x1 503x2", or "none".
func counts(m map[string]int) string {
	var keys []string
	for k, v := range m {
		if v > 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "none"
	}
	sort.Strings(keys)
	for i, k := range keys {
		keys[i] = fmt.Sprintf("%sx%d", k, m[k])
	}
	return strings.Join(keys, " ")
}

// workMark names the file that marks a scratch folder as this command's.
const workMark = ".gocalbox-load"

// emptyWork empties the scratch folder, which must be missing, empty, or one
// this command made, so that a mistyped -work can't delete anything else.
func emptyWork(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return err
	case len(entries) > 0:
		if _, err := os.Stat(filepath.Join(dir, workMark)); err != nil {
			return fmt.Errorf("-work %s holds files this command didn't make; give it a new or empty folder", dir)
		}
		if err := os.RemoveAll(dir); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, workMark), nil, 0o644)
}

func parseSize(s string) (int64, error) {
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("not a size")
	}
	return n * mult, nil
}

// gitState names the commit measured, and whether the tree has changes
// outside bench/, as the benchmark scripts do.
func gitState() (string, bool) {
	rev, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "unknown", false
	}
	dirty := exec.Command("git", "diff", "--quiet", "HEAD", "--", ".", ":!bench").Run() != nil
	return strings.TrimSpace(string(rev)), dirty
}
