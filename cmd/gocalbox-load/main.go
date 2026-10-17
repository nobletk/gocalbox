// Command gocalbox-load measures resumable uploads: simulated users each
// upload files through the engine as the browser does, and every repetition
// adds a line to a CSV file with the columns of the benchmark scripts.
//
// Only the in-process mode exists so far: the engine runs in this process
// with the real file operations, state file and audit log, but without HTTP
// and logins. Run it from the repository root.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/nobletk/gocalbox/bench/load"
)

func main() {
	work := flag.String("work", filepath.Join("bench", ".work", "load"), "Scratch folder; it must be on the disk being measured, and is emptied before each repetition")
	users := flag.Int("users", 1, "Simulated users uploading at once")
	files := flag.Int("files", 1, "Files each user uploads")
	size := flag.String("size", "64M", "Size of each file, in bytes or with K, M or G (IEC units)")
	parallel := flag.Int("parallel", 4, "Parts each user sends at once, across their files")
	reps := flag.Int("reps", 3, "Repetitions")
	auditWait := flag.Bool("audit-wait", true, "Completions answer only once their audit records are on disk, as the server does by default")
	auditParts := flag.Bool("audit-parts", false, "Record every accepted part in the audit log")
	minFreeMB := flag.Int64("min-free-mb", 1024, "Free space in MiB uploads must leave on the disk")
	csvPath := flag.String("csv", "", "CSV file to append to (default bench/results/<commit>-<time>-load.csv)")
	flag.Parse()

	bytes, err := parseSize(*size)
	if err != nil || *users < 1 || *files < 1 || *parallel < 1 || *reps < 1 {
		log.Fatalf("invalid flags: size %q (%v); users, files, parallel and reps must be at least 1", *size, err)
	}
	commit, dirty := gitState()
	if *csvPath == "" {
		*csvPath = filepath.Join("bench", "results", fmt.Sprintf("%s-%s-load.csv", commit, time.Now().Format("20060102-150405")))
	}
	if err := os.MkdirAll(filepath.Dir(*csvPath), 0o755); err != nil {
		log.Fatal(err)
	}
	_, statErr := os.Stat(*csvPath)
	out, err := os.OpenFile(*csvPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatal(err)
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
		if err := emptyWork(*work); err != nil {
			log.Fatal(err)
		}
		stack, err := load.NewStack(load.StackOptions{Work: *work, Users: *users, AuditWait: *auditWait,
			AuditParts: *auditParts, MinFree: *minFreeMB << 20})
		if err != nil {
			log.Fatal(err)
		}
		res := load.Run(context.Background(), load.Config{Users: stack.Users, Files: *files, Size: bytes, Parallel: *parallel})
		if err := stack.Close(); err != nil {
			log.Printf("closing the stack: %v", err)
		}
		fmt.Fprintln(out, res.Row(commit, dirty, scenario, bytes, *users**parallel, rep, "inprocess"))
		log.Printf("rep %d: %d of %d files uploaded in %.2fs, %.1f MiB/s, parts p50 %v p99 %v, %s",
			rep, res.Uploaded(), res.Files, res.Duration.Seconds(), float64(res.Bytes)/(1<<20)/res.Duration.Seconds(),
			res.Percentile(0.5).Round(time.Microsecond), res.Percentile(0.99).Round(time.Microsecond), res.CodeColumn())
	}
	if err := emptyWork(*work); err != nil {
		log.Printf("cannot empty %s: %v", *work, err)
	}
	log.Printf("results: %s", *csvPath)
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
