//go:build unix

package lib

import (
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/bench/load"
)

// server.sh crash kills the server with SIGKILL and starts it again on the
// same folder and state; the samples' CPU time goes on from where it was,
// and the environment file counts the crash.
func TestServerShCrashStartsTheServerAgain(t *testing.T) {
	serverTools(t)
	dir := benchDir(t)
	envDir := t.TempDir()
	env := []string{"BENCH_DIR=" + dir, "PORT=18471", "ENV_DIR=" + envDir}
	if out, ok := scriptArgs(t, []string{"server.sh", "crash"}, "", env...); ok || !strings.Contains(out, "no bench/server.sh is running") {
		t.Errorf("a crash without a server: %s", out)
	}
	cmd, console := serverSh(t, "", env...)
	ready := filepath.Join(dir, "server", "ready")
	waitFor(t, "the server", func() bool { return exists(ready) })
	old := readPID(t, ready)
	// Some CPU time for the samples to carry over the crash.
	for range 60 {
		exec.Command("curl", "-sk", "-o", "/dev/null", "https://127.0.0.1:18471/").Run()
	}
	time.Sleep(300 * time.Millisecond)
	before := lastCPU(t, filepath.Join(dir, "server", "samples.csv"))
	kept := filepath.Join(dir, "server", "root", "kept.bin")
	write(t, kept, "kept")
	// Kept busy through the crash, so that it uses CPU time after its last sample.
	busy := make(chan struct{})
	for range 16 {
		go func() {
			for {
				select {
				case <-busy:
					return
				default:
					exec.Command("curl", "-sk", "-o", "/dev/null", "https://127.0.0.1:18471/").Run()
				}
			}
		}()
	}
	time.Sleep(300 * time.Millisecond)
	out, ok := scriptArgs(t, []string{"server.sh", "crash"}, "", env...)
	close(busy)
	if !ok || !strings.Contains(out, "killed the server and started it again; it served again after ") {
		t.Fatalf("crash: %s", out)
	}
	crashed := time.Now()
	pid := readPID(t, ready)
	if pid == old || syscall.Kill(old, 0) == nil || syscall.Kill(pid, 0) != nil {
		t.Errorf("the server was %d and is %d", old, pid)
	}
	// Read while the killed server was stopped: no less than its last sample.
	if b, _ := os.ReadFile(filepath.Join(dir, "server", "killed-cpu")); !strings.HasPrefix(string(b), strconv.Itoa(old)+" ") {
		t.Errorf("killed-cpu %q", b)
	} else if kc, _ := strconv.ParseFloat(strings.TrimSpace(strings.Fields(string(b))[1]), 64); kc < before {
		t.Errorf("the killed server's CPU time %v, its last sample %v", kc, before)
	} else {
		// The restarted server's samples start from all of it.
		sb, _ := os.ReadFile(filepath.Join(dir, "server", "samples.csv"))
		for _, l := range strings.Split(strings.TrimSpace(string(sb)), "\n") {
			f := strings.Split(l, ",")
			at, _ := strconv.ParseFloat(f[0], 64)
			c, _ := strconv.ParseFloat(f[1], 64)
			if at > float64(crashed.UnixNano())/1e9 && c < kc {
				t.Errorf("a sample after the restart, %s, is below the killed server's %v", l, kc)
			}
		}
	}
	if !exists(kept) {
		t.Error("the restart emptied the served folder")
	}
	if code, err := exec.Command("curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "https://127.0.0.1:18471/").Output(); err != nil || string(code) != "200" {
		t.Errorf("after the crash: %s, %v", code, err)
	}
	// The restarted server is sampled too.
	for range 60 {
		exec.Command("curl", "-sk", "-o", "/dev/null", "https://127.0.0.1:18471/").Run()
	}
	time.Sleep(500 * time.Millisecond)
	samples := filepath.Join(dir, "server", "samples.csv")
	if after := lastCPU(t, samples); before <= 0 || after <= before {
		t.Errorf("CPU time %v before the crash, %v after", before, after)
	}
	// Idle now: the last sample is the killed server's CPU time and the new one's, to a tick.
	if b, err := os.ReadFile(filepath.Join(dir, "server", "killed-cpu")); err == nil {
		kc, _ := strconv.ParseFloat(strings.Fields(string(b))[1], 64)
		stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		f := strings.Fields(string(stat)[strings.LastIndex(string(stat), ")")+2:])
		ut, _ := strconv.ParseFloat(f[11], 64)
		st, _ := strconv.ParseFloat(f[12], 64)
		tick, _ := exec.Command("getconf", "CLK_TCK").Output()
		hz, _ := strconv.ParseFloat(strings.TrimSpace(string(tick)), 64)
		if last := lastCPU(t, samples); hz > 0 && math.Abs(last-(kc+(ut+st)/hz)) > 1.5/hz {
			t.Errorf("the last sample %v, the killed server's %v and the new one's %v", last, kc, (ut+st)/hz)
		}
	}
	if at := lastSampleTime(t, samples); at.Before(crashed.Add(300 * time.Millisecond)) {
		t.Errorf("the last sample, at %v, came before the restarted server's work, after %v", at, crashed)
	}
	// Killed, not shut down: a server that shuts down logs it.
	log, _ := os.ReadFile(filepath.Join(dir, "server", "server.log"))
	if strings.Count(string(log), "Starting server on") != 2 || !strings.Contains(string(log), "bench/server.sh: killed the server with SIGKILL; starting it again") ||
		strings.Contains(string(log), "Shutting down") {
		t.Errorf("server log:\n%s", log)
	}
	// Reaped meanwhile: stop waits for server.sh to end, which a zombie never does.
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	if out, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", env...); !ok {
		t.Fatalf("stop: %s\nconsole:\n%s", out, console())
	}
	<-ended
	if !strings.Contains(console(), "the server serves again after a crash") {
		t.Errorf("console:\n%s", console())
	}
	envs, _ := filepath.Glob(filepath.Join(envDir, "server-*-env.txt"))
	if len(envs) != 1 {
		t.Fatalf("environment files %q", envs)
	}
	if b, _ := os.ReadFile(envs[0]); !strings.Contains(string(b), "\ncrashes: 1\n") {
		t.Errorf("environment:\n%s", b)
	}
	if syscall.Kill(pid, 0) == nil {
		t.Error("the restarted server outlived its stop")
	}
	for _, f := range []string{"killed-cpu", "ready", "gocalbox.pid", "server.pid"} {
		if exists(filepath.Join(dir, "server", f)) {
			t.Errorf("%s is left after the stop", f)
		}
	}
}

func readPID(t *testing.T, path string) int {
	t.Helper()
	b, _ := os.ReadFile(path)
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("%s: %q", path, b)
	}
	return pid
}

func lastCPU(t *testing.T, samples string) float64 {
	t.Helper()
	b, _ := os.ReadFile(samples)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	f := strings.Split(lines[len(lines)-1], ",")
	cpu, err := strconv.ParseFloat(f[1], 64)
	if err != nil || len(f) != 3 {
		t.Fatalf("sample %q", lines[len(lines)-1])
	}
	prev, peak := 0.0, 0
	for _, l := range lines {
		f := strings.Split(l, ",")
		c, _ := strconv.ParseFloat(f[1], 64)
		rss, _ := strconv.Atoi(f[2])
		if c < prev || rss < peak {
			t.Errorf("the CPU time went from %v to %v, the peak memory from %d to %d kB", prev, c, peak, rss)
		}
		prev, peak = c, rss
	}
	return cpu
}

func lastSampleTime(t *testing.T, samples string) time.Time {
	t.Helper()
	b, _ := os.ReadFile(samples)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	sec, err := strconv.ParseFloat(strings.Split(lines[len(lines)-1], ",")[0], 64)
	if err != nil {
		t.Fatalf("sample %q", lines[len(lines)-1])
	}
	return time.Unix(0, int64(sec*1e9))
}

// A server that can't start again ends its server.sh, and crash says so at once.
func TestServerShCrashSaysWhenTheServerCantStartAgain(t *testing.T) {
	serverTools(t)
	dir := benchDir(t)
	env := []string{"BENCH_DIR=" + dir, "PORT=18475", "ENV_DIR=" + t.TempDir()}
	cmd, console := serverSh(t, "", env...)
	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()
	waitFor(t, "the server", func() bool { return exists(filepath.Join(dir, "server", "ready")) })
	bin := filepath.Join(dir, "server", "gocalbox")
	write(t, bin+".new", "#!/bin/sh\nexit 1\n")
	os.Chmod(bin+".new", 0o755)
	if err := os.Rename(bin+".new", bin); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, ok := scriptArgs(t, []string{"server.sh", "crash"}, "", env...)
	if ok || !strings.Contains(out, "bench/server.sh ended instead of starting the server again") || time.Since(start) > 30*time.Second {
		t.Errorf("crash, after %v: %s", time.Since(start), out)
	}
	if err := <-ended; err == nil || !strings.Contains(console(), "the server didn't start again") {
		t.Errorf("server.sh: %v\n%s", err, console())
	}
}

// A session over ssh crashes its server at a share of each file and goes on
// with the server started again; its seeks fetch their ranges, each one in
// the session's seeks file, and the row's latencies are theirs.
func TestASessionWithCrashesAndSeeks(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	client, server := benchDir(t), benchDir(t)
	bin, log := fakeRemote(t)
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, `server s
cell kill  s engine size=17M fault=kill fault-at=0.5 retry-for=1m
cell seek  s seek size=1M seeks=5 chunk=64K transport=https-h1
cell seek2 s seek size=256K seeks=5 chunk=200K
`)
	// The page cache is dropped through sudo on the server, which here only logs it.
	drops := filepath.Join(t.TempDir(), "drops")
	write(t, filepath.Join(bin, "sudo"), "#!/bin/sh\necho \"$*\" >> "+drops+"\n")
	os.Chmod(filepath.Join(bin, "sudo"), 0o755)
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, "BENCH_DIR="+client, "SERVER_SSH=bench@server", "SERVER_HOST=localhost",
		"SERVER_BENCH="+server, "SERVER_REPO="+repo, "PORT=18472", "REPS=1", "WARMUP=1", "DROP_CACHES=1", "IPERF=0", "CELLS=")
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	// Once to try it at the start, then before each of the 4 seek runs.
	if b, _ := os.ReadFile(drops); strings.Count(string(b), "-n sh -c echo 3 > /proc/sys/vm/drop_caches\n") != 5 || strings.Count(string(b), "\n") != 5 {
		t.Errorf("drops:\n%s", b)
	}
	checkSession(t, out, client, server)
	if b, _ := os.ReadFile(log); strings.Count(string(b), "bench/server.sh crash") != 2 {
		t.Errorf("ssh calls:\n%s", b)
	}
	header := strings.Split(load.Header, ",")
	col := func(row []string, name string) string { return row[slices.Index(header, name)] }
	rows := map[string][]string{}
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
		row := strings.Split(line, ",")
		rows[col(row, "scenario")+" "+col(row, "rep")] = row
	}
	for _, rep := range []string{"0", "1"} {
		if row := rows["kill "+rep]; col(row, "resumed") != "1" || col(row, "http_code") != "201" {
			t.Errorf("kill %s: %q", rep, row)
		}
	}
	_, rest, _ := strings.Cut(out, "results: ")
	base, _, _ := strings.Cut(rest, "\n")
	seeks, err := os.ReadFile(filepath.Join("..", "..", strings.TrimSuffix(strings.TrimSpace(base), ".csv")+"-seeks.csv"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(seeks)), "\n")
	if lines[0] != "seq,cell,rep,seek,offset,bytes,http_code,first_byte_ms,ms" || len(lines) != 1+2*5+2*5 {
		t.Fatalf("seeks:\n%s", seeks)
	}
	order := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")[1:] {
		f := strings.Split(line, ",")
		order[f[0]] = f[2] + " " + f[3]
	}
	times := map[string][]float64{}
	offsets := map[string][]string{}
	for _, line := range lines[1:] {
		f := strings.Split(line, ",")
		run := order[f[0]]
		size, chunk := 1<<20, 64<<10
		if strings.HasPrefix(run, "seek2 ") {
			size, chunk = 256<<10, 200<<10
		}
		off, _ := strconv.Atoi(f[4])
		ms, _ := strconv.ParseFloat(f[8], 64)
		first, _ := strconv.ParseFloat(f[7], 64)
		if f[1]+" "+f[2] != run || f[3] != strconv.Itoa(len(times[run])+1) || off < 0 || off > size-chunk || f[5] != strconv.Itoa(chunk) ||
			f[6] != "206" || first <= 0 || ms < first {
			t.Errorf("seek %s of run %s", line, run)
		}
		times[run] = append(times[run], ms)
		offsets[run] = append(offsets[run], f[4])
	}
	if slices.Equal(offsets["seek 0"], offsets["seek 1"]) {
		t.Errorf("both repetitions seek to %q", offsets["seek 0"])
	}
	for run, ts := range times {
		row := rows[run]
		var sum float64
		for _, x := range ts {
			sum += x
		}
		sorted := slices.Clone(ts)
		slices.Sort(sorted)
		at := func(p float64) float64 { return sorted[min(int(p*float64(len(sorted))), len(sorted)-1)] }
		want := []string{fmt.Sprintf("%.6f", sum/1000), fmt.Sprintf("%.3f", at(0.5)), fmt.Sprintf("%.3f", at(0.99)), strconv.Itoa(len(ts))}
		got := []string{col(row, "seconds"), col(row, "part_p50_ms"), col(row, "part_p99_ms"), col(row, "files")}
		if !slices.Equal(got, want) || col(row, "http_code") != "206" {
			t.Errorf("run %s: seconds, p50, p99 and seeks %q, want %q; row %q", run, got, want, row)
		}
	}
}

// After a crash the session watches the server by its new PID: a run that
// fails after it doesn't take the server for stopped.
func TestASessionWatchesTheServerItCrashedByItsNewPID(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	dir := benchDir(t)
	matrix := "server s SERVER_FLAGS=-max-upload-mb=20\ncell kill s engine size=17M fault=kill fault-at=0.5 retry-for=1m\ncell big s engine size=30M\n"
	// A seed whose order has a failing run after a crash.
	seed := ""
	for n := 1; n < 50 && seed == ""; n++ {
		plan := planOf(t, dir, matrix, "SEED="+strconv.Itoa(n), "REPS=2", "WARMUP=0", "ROUNDS=1")
		if k := slices.IndexFunc(plan, func(r string) bool { return strings.Contains(r, " kill ") }); k >= 0 &&
			slices.ContainsFunc(plan[k:], func(r string) bool { return strings.Contains(r, " big ") }) {
			seed = strconv.Itoa(n)
		}
	}
	m := filepath.Join(t.TempDir(), "m.txt")
	write(t, m, matrix)
	out, ok := scriptArgs(t, []string{"session.sh", m}, "", "BENCH_DIR="+dir, "PORT=18473", "SEED="+seed, "REPS=2", "WARMUP=0", "ROUNDS=1",
		"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
	if !ok || !strings.Contains(out, "warning: 2 runs were not ok") {
		t.Fatalf("session.sh: %s", out)
	}
	order := output(t, out, "order")
	if strings.Count(order, ",answered 413x1") != 2 || strings.Count(order, ",ok") != 2 || strings.Contains(order, "skipped") {
		t.Errorf("order:\n%s", order)
	}
	if env := output(t, out, "environment"); strings.Contains(env, "the rest of its block's runs are skipped") {
		t.Errorf("environment:\n%s", env)
	}
}

// fakeSudo is a sudo that runs its command, as a rule for NETCUT would;
// with refuse set, it runs nothing.
func fakeSudo(t *testing.T, bin string, refuse bool) {
	t.Helper()
	run := `exec "$@"`
	if refuse {
		run = `echo "sudo: a password is required" >&2; exit 1`
	}
	write(t, filepath.Join(bin, "sudo"), `#!/bin/bash
[ "$1" = -n ] || { echo "fake sudo: not -n" >&2; exit 1; }
shift
`+run+`
`)
	os.Chmod(filepath.Join(bin, "sudo"), 0o755)
}

// A cut cell runs NETCUT through sudo, with the server's address and
// cut-for, once a file has its share in; the session refuses to start
// without a NETCUT owned by root that sudo may run.
func TestASessionCutsTheNetworkThroughNetcut(t *testing.T) {
	sessionTools(t)
	if os.Geteuid() != 0 {
		t.Skip("NETCUT must be owned by root, and only root can make one")
	}
	keepResults(t)
	client, server := benchDir(t), benchDir(t)
	bin, _ := fakeRemote(t)
	fakeSudo(t, bin, false)
	cuts := filepath.Join(t.TempDir(), "cuts")
	netcut := filepath.Join(t.TempDir(), "netcut")
	write(t, netcut, "#!/bin/sh\necho \"$*\" >> "+cuts+"\nsleep 0.5\n")
	os.Chmod(netcut, 0o755)
	repo, _ := filepath.Abs(filepath.Join("..", ".."))
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server s\ncell cut s engine size=17M fault=cut fault-at=0.5 retry-for=1m cut-for=7\n")
	env := []string{"BENCH_DIR=" + client, "SERVER_SSH=bench@server", "SERVER_HOST=127.0.0.1", "SERVER_BENCH=" + server, "SERVER_REPO=" + repo,
		"PORT=18474", "REPS=1", "WARMUP=1", "DROP_CACHES=0", "IPERF=0", "CELLS=", "NETCUT=" + netcut}
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, env...)
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	checkSession(t, out, client, server)
	// The first is the check before the session.
	if b, _ := os.ReadFile(cuts); string(b) != "192.0.2.1 1\n127.0.0.1 7\n127.0.0.1 7\n" {
		t.Errorf("cuts %q", b)
	}
	if !strings.Contains(out, "differs from bench/lib/netcut.sh") || !strings.Contains(output(t, out, "environment"), "network cuts: "+netcut+", to 127.0.0.1") {
		t.Errorf("session.sh: %s", out)
	}

	refused := t.TempDir()
	fakeRemote2, _ := fakeRemote(t)
	fakeSudo(t, refused, true)
	missing := filepath.Join(t.TempDir(), "missing")
	for _, c := range []struct {
		bin, netcut, want string
	}{
		{bin, missing, "cut cells need " + missing + ": bench/lib/netcut.sh installed as root"},
		{refused + string(os.PathListSeparator) + fakeRemote2, netcut, "cut cells need sudo to run " + netcut + " without a password (bench/README.md): sudo: a password is required"},
	} {
		out, ok := scriptArgs(t, []string{"session.sh", matrix}, c.bin, append(slices.Clone(env), "NETCUT="+c.netcut)...)
		if ok || !strings.Contains(out, c.want) {
			t.Errorf("NETCUT=%s: %s", c.netcut, out)
		}
	}
	os.Chown(netcut, 65534, 65534)
	if out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, env...); ok || !strings.Contains(out, "bench/lib/netcut.sh installed as root") {
		t.Errorf("a NETCUT not owned by root: %s", out)
	}
}

// netcut.sh takes one IPv4 or IPv6 address and whole seconds from 1 to 60,
// and runs only as root.
func TestNetcutChecksItsArguments(t *testing.T) {
	needBash(t)
	for _, c := range []struct {
		args []string
		want string
		code int
	}{
		{nil, "usage: gocalbox-netcut ADDRESS SECONDS", 2},
		{[]string{"1.2.3.4"}, "usage", 2},
		{[]string{"1.2.3.4", "10", "x"}, "usage", 2},
		{[]string{"1.2.3.4", "0"}, "SECONDS must be a whole number from 1 to 60", 2},
		{[]string{"1.2.3.4", "61"}, "SECONDS must be", 2},
		{[]string{"1.2.3.4", "010"}, "SECONDS must be", 2},
		{[]string{"1.2.3.4", "1.5"}, "SECONDS must be", 2},
		{[]string{"1.2.3.4", ""}, "SECONDS must be", 2},
		{[]string{"1.2.3", "10"}, "not an IPv4 or IPv6 address: 1.2.3", 2},
		{[]string{"256.1.1.1", "10"}, "not an IPv4", 2},
		{[]string{"01.2.3.4", "10"}, "not an IPv4", 2},
		{[]string{"1.2.3.4;reboot", "10"}, "not an IPv4", 2},
		{[]string{"fe80::1%eth0", "10"}, "not an IPv4", 2},
		{[]string{"::ffff:1.2.3.4", "10"}, "not an IPv4", 2},
		{[]string{"g::1", "10"}, "not an IPv4", 2},
		{[]string{"1:2:3:4:5:6:7:8:9", "10"}, "not an IPv4", 2},
		{[]string{"1:2:3:4:5:6:7", "10"}, "not an IPv4", 2},
		{[]string{"1::2::3", "10"}, "not an IPv4", 2},
		{[]string{"12345::1", "10"}, "not an IPv4", 2},
		{[]string{"", "10"}, "not an IPv4", 2},
		{[]string{"1.2.3.4\nadd table inet injected", "1"}, "not an IPv4", 2},
		{[]string{"1.2.3.4\n", "1"}, "not an IPv4", 2},
		{[]string{"::1\nadd table inet injected", "1"}, "not an IPv4", 2},
		{[]string{"1.2.3.4", "1\n"}, "SECONDS must be", 2},
	} {
		cmd := exec.Command("sh", append([]string{filepath.Join("..", "..", "bench", "lib", "netcut.sh")}, c.args...)...)
		out, err := cmd.CombinedOutput()
		code := 0
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		}
		if code != c.code || !strings.Contains(string(out), c.want) {
			t.Errorf("%q: %d %s; want %d %q", c.args, code, out, c.code, c.want)
		}
	}
	if os.Geteuid() != 0 {
		out, err := exec.Command("sh", filepath.Join("..", "..", "bench", "lib", "netcut.sh"), "192.0.2.1", "1").CombinedOutput()
		if err == nil || !strings.Contains(string(out), "must run as root, through sudo") {
			t.Errorf("not root: %s, %v", out, err)
		}
	}
}

// netcut.sh drops the traffic to and from its address only, for its
// seconds, even when it is killed meanwhile, and leaves no table behind.
func TestNetcutCutsOneAddressForItsSeconds(t *testing.T) {
	needBash(t)
	if os.Geteuid() != 0 {
		t.Skip("cutting needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("no nft")
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("nft can't be used here: %s", out)
	}
	cut, other := listen(t, "127.0.0.42"), listen(t, "127.0.0.43")
	script := filepath.Join("..", "..", "bench", "lib", "netcut.sh")
	for _, kill := range []bool{false, true} {
		cmd := exec.Command("sh", script, "127.0.0.42", "2")
		start := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the cut", func() bool { return exec.Command("nft", "list", "table", "inet", "gocalbox_bench").Run() == nil })
		if kill {
			cmd.Process.Kill()
		}
		if reach(cut) {
			t.Errorf("killed %v: reached the address cut off", kill)
		}
		if !reach(other) {
			t.Errorf("killed %v: another address was cut off too", kill)
		}
		for time.Since(start) < 2500*time.Millisecond {
			time.Sleep(100 * time.Millisecond)
		}
		if !reach(cut) {
			t.Errorf("killed %v: the address is still cut off after 2.5 s", kill)
		}
		cmd.Wait()
		if !kill && exec.Command("nft", "list", "table", "inet", "gocalbox_bench").Run() == nil {
			t.Error("the table is left behind")
		}
	}
	// A table a killed run left behind is replaced by the next cut, and deleted after it.
	if out, err := exec.Command("sh", script, "127.0.0.42", "1").CombinedOutput(); err != nil || !strings.Contains(string(out), "127.0.0.42 is reachable again") {
		t.Errorf("after a killed cut: %s, %v", out, err)
	}
	if exec.Command("nft", "list", "table", "inet", "gocalbox_bench").Run() == nil {
		t.Error("the table is left behind")
	}
}

func listen(t *testing.T, addr string) string {
	t.Helper()
	l, err := net.Listen("tcp", addr+":0")
	if err != nil {
		t.Skipf("can't listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().String()
}

func reach(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// tamperingCurl is a curl that changes what the seeks get, as the file named
// by its control file says: their first status or length, their count, or
// the content of the first range written to a file.
func tamperingCurl(t *testing.T) (bin, control string) {
	t.Helper()
	real, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("no curl")
	}
	bin = t.TempDir()
	control = filepath.Join(bin, "mode")
	write(t, control, "")
	write(t, filepath.Join(bin, "curl"), `#!/bin/bash
case " $* " in *" -r "*) ;; *) exec `+real+` "$@" ;; esac
mode=$(cat `+control+`)
out=$(`+real+` "$@"); code=$?
case $mode in
  status) out=$(sed '1s/^206,/200,/' <<< "$out") ;;
  length) out=$(sed '1s/^206,[0-9]*,/206,1,/' <<< "$out") ;;
  count) out=$(sed '$d' <<< "$out") ;;
  content)
    prev=
    for a in "$@"; do
      if [ "$prev" = -o ] && [ "$a" != /dev/null ]; then printf 'X' | dd of="$a" bs=1 count=1 conv=notrunc 2> /dev/null; break; fi
      prev=$a
    done ;;
esac
printf '%s\n' "$out"
exit $code
`)
	os.Chmod(filepath.Join(bin, "curl"), 0o755)
	return bin, control
}

// A seek that answers other than 206, with other than its length, not at
// all, or, in a warm-up, with other bytes, marks its run; so does a file
// placed for the seeks that isn't the source's.
func TestASessionMarksAWrongSeek(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	bin, control := tamperingCurl(t)
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server s\ncell seek s seek size=256K seeks=3 chunk=1K\n")
	header := strings.Split(load.Header, ",")
	for _, c := range []struct {
		mode, outcome0, code0, outcome1, code1 string
	}{
		{"status", "seek 1 answered 200", "200", "seek 1 answered 200", "200"},
		{"length", "seek 1 got 1 of 1024 bytes", "206 wrong_size", "seek 1 got 1 of 1024 bytes", "206 wrong_size"},
		{"count", "got 2 of 3 answers", "000", "got 2 of 3 answers", "000"},
		{"content", "seek 1 got other bytes", "206 wrong_file", "ok", "206"},
		{"", "the file placed for it isn't the source's bytes", "206 wrong_file", "the file placed for it isn't the source's bytes", "206 wrong_file"},
	} {
		dir := benchDir(t)
		if c.mode == "" {
			content := strings.Repeat("z", 256<<10)
			write(t, filepath.Join(dir, "data", "fixed-256K.bin"), content)
			write(t, filepath.Join(dir, "data", "fixed-256K.bin.sha256"), strings.Repeat("0", 64)+"\n")
		}
		write(t, control, c.mode)
		out, _ := scriptArgs(t, []string{"session.sh", matrix}, bin, "BENCH_DIR="+dir, "PORT=18476", "REPS=1", "WARMUP=1",
			"DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")
		order := output(t, out, "order")
		outcomes := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(order), "\n")[1:] {
			f := strings.Split(line, ",")
			outcomes[f[3]] = f[7]
		}
		codes := map[string]string{}
		for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
			row := strings.Split(line, ",")
			codes[row[slices.Index(header, "rep")]] = row[slices.Index(header, "http_code")]
		}
		if outcomes["0"] != c.outcome0 || outcomes["1"] != c.outcome1 || codes["0"] != c.code0 || codes["1"] != c.code1 {
			t.Errorf("%q: outcomes %q, codes %q", c.mode, outcomes, codes)
		}
	}
}

// A cut drops both ways, by the source going in and the destination going
// out; a second cut while one runs is refused at once; and a table a killed
// run left behind, whatever it holds, is replaced.
func TestNetcutsTableAndLock(t *testing.T) {
	needBash(t)
	if os.Geteuid() != 0 {
		t.Skip("cutting needs root")
	}
	if out, err := exec.Command("nft", "list", "tables").CombinedOutput(); err != nil {
		t.Skipf("nft can't be used here: %s", out)
	}
	other := listen(t, "127.0.0.43")
	stale := "table inet gocalbox_bench { chain x { type filter hook output priority 0; policy accept; ip daddr 127.0.0.43 drop; }; }"
	if out, err := exec.Command("nft", stale).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", "gocalbox_bench").Run() })
	script := filepath.Join("..", "..", "bench", "lib", "netcut.sh")
	cmd := exec.Command("sh", script, "127.0.0.42", "2")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the cut", func() bool {
		out, _ := exec.Command("nft", "list", "table", "inet", "gocalbox_bench").Output()
		return strings.Contains(string(out), "127.0.0.42")
	})
	out, _ := exec.Command("nft", "list", "table", "inet", "gocalbox_bench").Output()
	rules := strings.Join(strings.Fields(string(out)), " ")
	for _, want := range []string{"chain input { type filter hook input priority raw; policy accept; ip saddr @cut drop }",
		"chain output { type filter hook output priority raw; policy accept; ip daddr @cut drop }"} {
		if !strings.Contains(rules, want) {
			t.Errorf("no %q in %s", want, rules)
		}
	}
	if strings.Contains(rules, "chain x") || !reach(other) {
		t.Errorf("the table left behind is still there: %s", rules)
	}
	start := time.Now()
	second, err := exec.Command("sh", script, "127.0.0.44", "1").CombinedOutput()
	if err == nil || !strings.Contains(string(second), "another cut is running") || time.Since(start) > time.Second {
		t.Errorf("a second cut, after %v: %s, %v", time.Since(start), second, err)
	}
	cmd.Wait()
}
