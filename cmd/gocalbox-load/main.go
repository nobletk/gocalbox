// Command gocalbox-load measures resumable uploads: simulated users each
// upload files as the browser does, and every repetition adds a line to a
// CSV file with the columns of the benchmark scripts.
//
// By default the engine runs in this process with the real file operations,
// state file and audit log, but without HTTP and logins, in the subfolder
// load of the benchmark folder made with bench/init.sh. With -url the users
// upload to a running server over HTTPS instead, each logged in over a
// connection of its own: the users <prefix>00, <prefix>01, … must exist,
// made with gocalbox users add as contributors with the one password this
// command reads from standard input. What they uploaded is deleted after
// each repetition. The CSV names the commit of this tree, which should
// then be the server's. Run it from the repository root.
package main

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/bench/lib"
	"github.com/nobletk/gocalbox/bench/load"
	"github.com/nobletk/gocalbox/internal/benchmode"
	"github.com/nobletk/gocalbox/internal/transfer"
)

func main() {
	err := run(os.Args[1:], os.Stdin, os.Stdout)
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

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	fl := flag.NewFlagSet("gocalbox-load", flag.ContinueOnError)
	benchDir := fl.String("bench-dir", os.Getenv("BENCH_DIR"), "The benchmark folder, made with bench/init.sh on the disk being measured; the engine works in its subfolder load, which is emptied before each repetition (in-process only; default $BENCH_DIR)")
	work := fl.String("work", "", "Replaced by -bench-dir")
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
	resumeAt := fl.Float64("resume-at", 0, "Stop each file once this share of its parts is in, such as 0.5, then resume it by its client key as the browser does; 0 never stops")
	retryFor := fl.Duration("retry-for", 0, "Try calls that get no answer, or find the server shutting down, again for up to this long, such as 2m; 0 ends the file at once")
	header := fl.Bool("header", false, "Print the CSV file's first line and exit")
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return errUsage
	}

	if *header {
		fmt.Fprintln(stdout, load.Header)
		return nil
	}
	if *work != "" {
		return errors.New("-work is replaced by -bench-dir, a folder made with bench/init.sh")
	}
	bytes, err := parseSize(*size)
	if err != nil || *users < 1 || *files < 1 || *parallel < 1 || *reps < 1 {
		return fmt.Errorf("invalid flags: size %q (%v); users, files, parallel and reps must be at least 1", *size, err)
	}
	if !(*resumeAt >= 0 && *resumeAt < 1) || *retryFor < 0 {
		return fmt.Errorf("invalid flags: -resume-at must be at least 0 and below 1, and -retry-for not negative")
	}
	set := map[string]bool{}
	fl.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if err := checkModes(set, *url != "", *transport); err != nil {
		return err
	}
	if err := benchmode.Init(); err != nil {
		return err
	}
	var bench *lib.Folder
	if *url == "" {
		if bench, err = lib.Use(*benchDir); err != nil {
			return err
		}
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
	out, err := openCSV(*csvPath)
	if err != nil {
		return err
	}
	defer out.Close()

	scenario := fmt.Sprintf("engine_upload_%du", *users)
	if *auditParts {
		scenario += "_audit_parts"
	}
	if !*auditWait {
		scenario += "_no_wait"
	}
	if *resumeAt > 0 {
		scenario += fmt.Sprintf("_resume%g", *resumeAt*100)
	}
	cfg := load.Config{Users: remote, Files: *files, Size: bytes, Parallel: *parallel, ResumeAt: *resumeAt, RetryFor: *retryFor}
	for rep := 1; rep <= *reps; rep++ {
		var res load.Result
		var server string
		column := "inprocess"
		if remote != nil {
			column = *transport
			res = load.Run(context.Background(), cfg)
		} else {
			work := filepath.Join(bench.Dir, "load")
			if err := bench.Remove(work); err != nil {
				return err
			}
			if err := os.Mkdir(work, 0o755); err != nil {
				return err
			}
			stack, err := load.NewStack(load.StackOptions{Work: work, Users: *users, AuditWait: *auditWait,
				AuditParts: *auditParts, MinFree: *minFreeMB << 20})
			if err != nil {
				return err
			}
			cfg.Users = stack.Users
			res = load.Run(context.Background(), cfg)
			server = "; " + engineSummary(stack.Engine.Stats())
			if err := stack.Close(); err != nil {
				log.Printf("closing the stack: %v", err)
			}
		}
		fmt.Fprintln(out, res.Row(commit, dirty, scenario, bytes, *users**parallel, rep, column))
		log.Printf("rep %d: %d of %d files uploaded in %.2fs, %.1f MiB/s, parts p50 %v p99 %v, %s, tried again %s, resent %d bytes, %d resumed, CPU %v%s",
			rep, res.Uploaded(), res.Files, res.Duration.Seconds(), float64(res.Bytes)/(1<<20)/res.Duration.Seconds(),
			res.Percentile(0.5).Round(time.Microsecond), res.Percentile(0.99).Round(time.Microsecond), res.CodeColumn(),
			cmp.Or(load.Counts(res.Retried), "none"), res.Resent, len(res.Resumes), res.CPU.Round(time.Millisecond), server)
		if remote != nil {
			if err := load.Clean(context.Background(), remote); err != nil {
				return fmt.Errorf("removing what rep %d uploaded: %w", rep, err)
			}
		}
	}
	if bench != nil {
		if err := bench.Remove(filepath.Join(bench.Dir, "load")); err != nil {
			log.Printf("cannot delete what the engine wrote: %v", err)
		}
	}
	log.Printf("results: %s", *csvPath)
	return nil
}

// checkModes refuses the flags of the mode not chosen, which would go
// unused without a word.
func checkModes(set map[string]bool, remote bool, transport string) error {
	other, mode := []string{"bench-dir", "audit-wait", "audit-parts", "min-free-mb"}, "the in-process mode; set them on the server"
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

// openCSV opens the CSV file to append to, with its header if it is new.
// A file with other columns, such as a script's, is refused.
func openCSV(path string) (*os.File, error) {
	out, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	first, err := bufio.NewReader(out).ReadString('\n')
	switch {
	case err == io.EOF && first == "":
		_, err = fmt.Fprintln(out, load.Header)
	case err != nil && err != io.EOF:
	case strings.TrimRight(first, "\r\n") != load.Header:
		err = fmt.Errorf("-csv %s has other columns than this command writes; give a new file", path)
	default:
		err = endLine(out)
	}
	if err != nil {
		out.Close()
		return nil, err
	}
	return out, nil
}

// endLine ends the file's last line, if it has none, so that the next row
// starts a line of its own.
func endLine(f *os.File) error {
	fi, err := f.Stat()
	if err != nil || fi.Size() == 0 {
		return err
	}
	last := make([]byte, 1)
	if _, err := f.ReadAt(last, fi.Size()-1); err != nil {
		return err
	}
	if last[0] != '\n' {
		_, err = f.Write([]byte{'\n'})
	}
	return err
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

// engineSummary is what the log line of a repetition says of the engine
// run in process.
func engineSummary(st transfer.Stats) string {
	return fmt.Sprintf("the engine: %d parts, %d duplicates, refused busy %d (%d waits ran out, %d found the queue full), too_many_requests %d, too_many_uploads %d; %d parts waited for a slot, %v in all",
		st.PartsReceived, st.Duplicates, st.Busy, st.WaitTimeouts, st.QueueFull, st.TooManyRequests, st.TooManyUploads, st.Waited, st.WaitTime.Round(time.Millisecond))
}
