package lib

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nobletk/gocalbox/bench/load"
)

// fakeBaselines puts stand-ins for tusd, sshd and OpenSSH's client tools in
// a folder for PATH, and returns it with the environment they share.
func fakeBaselines(t *testing.T) (bin string, env []string) {
	t.Helper()
	bin = t.TempDir()
	for name, pkg := range map[string]string{"tusd": "./bench/lib/testdata/faketusd", "sshd": "./bench/lib/testdata/fakesshd"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(bin, name), pkg)
		cmd.Dir = filepath.Join("..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("building the fake %s: %v\n%s", name, err, out)
		}
	}
	for _, name := range []string{"sftp", "scp", "ssh", "ssh-keygen", "fakessh.sh"} {
		b, err := os.ReadFile(filepath.Join("testdata", "fakessh", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bin, name), b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return bin, []string{"FAKE_SSH_STATE=" + t.TempDir()}
}

const baselineMatrix = `server tusd KIND=tusd
server ssh  KIND=sshd
server g
cell t-h2   tusd tus transport=https-h2 size=3M chunk=1M
cell t-h1   tusd tus transport=https-h1 size=64K
cell t-one  tusd tus size=3M chunk=0
cell t-stop tusd tus size=3M chunk=1M resume-at=0.5
cell sp     ssh  sftp-put size=64K files=3
cell sg     ssh  sftp-get size=1M
cell sc     ssh  scp-put size=64K
cell e1     g    engine size=64K parallel=1
`

// A session with the baselines: tusd's rows come from the load client's tus
// mode, sshd's from sftp and scp, each checked against the source, with the
// server's CPU, sshd's sessions included; nothing is left behind but the
// servers' own folders.
func TestASessionWithTheBaselines(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	bin, env := fakeBaselines(t)
	dir := benchDir(t)
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, baselineMatrix)
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, append(env, "BENCH_DIR="+dir, "PORT=18394", "REPS=1", "WARMUP=1",
		"ROUNDS=2", "DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")...)
	if !ok {
		t.Fatalf("session.sh: %s", out)
	}
	csv := strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")
	order := strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")
	if csv[0] != load.Header || len(csv) != 17 || len(order) != 17 {
		t.Fatalf("%d rows and %d runs, want 16:\n%s", len(csv)-1, len(order)-1, strings.Join(csv, "\n"))
	}
	for _, line := range order[1:] {
		if !strings.HasSuffix(line, ",ok") {
			t.Errorf("run %s", line)
		}
	}
	header := strings.Split(load.Header, ",")
	seen := map[string]int{}
	for _, line := range csv[1:] {
		row := strings.Split(line, ",")
		col := func(name string) string { return row[slices.Index(header, name)] }
		num := func(name string) float64 { f, _ := strconv.ParseFloat(col(name), 64); return f }
		id := col("scenario")
		seen[id]++
		want := map[string]struct{ code, transport, size, files string }{
			"t-h2": {"201", "https-h2", "3145728", "1"}, "t-h1": {"201", "https-h1", "65536", "1"}, "t-one": {"201", "https-h2", "3145728", "1"},
			"t-stop": {"201", "https-h2", "3145728", "1"}, "sp": {"201", "ssh", "65536", "3"}, "sg": {"200", "ssh", "1048576", "1"},
			"sc": {"201", "ssh", "65536", "1"}, "e1": {"201", "https-h2", "65536", "1"},
		}[id]
		if col("http_code") != want.code || col("transport") != want.transport || col("size_bytes") != want.size || col("files") != want.files ||
			num("seconds") <= 0 || col("server_cpu_s") == "" || col("started_unix") == "" {
			t.Errorf("row %s", line)
		}
		switch id {
		case "t-h2", "t-h1", "t-one", "t-stop":
			// The load client's own columns, and the time to flush the file stored.
			if col("part_p50_ms") == "" || col("client_cpu_s") == "" || num("durable_upper_seconds") <= num("seconds") {
				t.Errorf("tus row %s", line)
			}
			if (id == "t-stop") != (col("resumed") == "1") {
				t.Errorf("resumed in row %s", line)
			}
		case "sp", "sc":
			if num("durable_upper_seconds") <= num("seconds") || num("server_cpu_s") < 0.01 {
				t.Errorf("ssh row %s", line)
			}
		case "sg":
			if col("durable_upper_seconds") != "" || num("server_cpu_s") < 0.01 {
				t.Errorf("ssh row %s", line)
			}
		}
	}
	if len(seen) != 8 {
		t.Errorf("rows of %v", seen)
	}
	envFile := output(t, out, "environment")
	for _, want := range []string{"server ssh: OpenSSH_fake, OpenSSL fake; client: OpenSSH_fake client", "  server->client cipher: fake-cipher",
		"  client->server cipher: fake-cipher", "  algorithm: fake-kex", "not ok: 0"} {
		if !strings.Contains(envFile, want) {
			t.Errorf("the environment file has no %q:\n%s", want, envFile)
		}
	}
	if strings.Count(envFile, "server ssh: OpenSSH_fake") != 1 {
		t.Error("sshd's algorithms are recorded more than once")
	}
	_, rest, _ := strings.Cut(out, "results: ")
	base, _, _ := strings.Cut(rest, "\n")
	base = filepath.Join("..", "..", strings.TrimSuffix(strings.TrimSpace(base), ".csv"))
	for srv, want := range map[string]string{"tusd": "kind: tusd   version: Version: faketusd", "ssh": "kind: sshd   version: OpenSSH_fake"} {
		b, _ := os.ReadFile(base + "-server-" + srv + "-env.txt")
		if strings.Count(string(b), want) != 2 || !strings.Contains(string(b), "console event log: on, every request, with -verbose=false") && srv == "tusd" {
			t.Errorf("server %s's environment:\n%s", srv, b)
		}
	}
	if b, _ := os.ReadFile(base + "-server-tusd.log"); strings.Contains(string(b), "PATCH") {
		t.Error("tusd logged its requests though the console log is off")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "session"))
	for _, e := range entries {
		if e.Name() != "load.log" {
			t.Errorf("left in the session folder: %s", e.Name())
		}
	}
	if exists(filepath.Join(dir, "server", "tls-tusd", "ca.key")) || !exists(filepath.Join(dir, "server", "tls-tusd", "ca.crt")) {
		t.Error("tusd's CA key is left, or its certificate is gone")
	}
	// sshd's CPU, sampled over its processes, never goes back within a block.
	sb, _ := os.ReadFile(base + "-server-ssh-samples.csv")
	last := map[string]float64{}
	for _, line := range strings.Split(strings.TrimSpace(string(sb)), "\n") {
		f := strings.Split(line, ",")
		cpu, _ := strconv.ParseFloat(f[1], 64)
		if cpu < last[f[3]] {
			t.Errorf("sshd's CPU fell from %g to %g in round %s", last[f[3]], cpu, f[3])
		}
		last[f[3]] = cpu
	}
	root, _ := os.ReadDir(filepath.Join(dir, "server", "root"))
	for _, e := range root {
		if !slices.Contains([]string{".gocalbox", "public", "users"}, e.Name()) {
			t.Errorf("left in the served folder: %s", e.Name())
		}
	}
}

// The matrix takes a baseline's tool only against a server of its kind.
func TestTheMatrixMatchesToolsToKinds(t *testing.T) {
	needBash(t)
	keepResults(t)
	dir := benchDir(t)
	plan := func(matrix string) (string, bool) {
		m := filepath.Join(t.TempDir(), "m.txt")
		write(t, m, matrix)
		return scriptArgs(t, []string{"session.sh", m}, "", "BENCH_DIR="+dir, "PLAN_ONLY=1", "SERVER_SSH=", "CELLS=")
	}
	if out, ok := plan(baselineMatrix); !ok {
		t.Fatalf("a good matrix: %s", out)
	}
	for _, c := range []struct{ matrix, want string }{
		{"server g\ncell x g tus size=1M\n", "tus measures a server of KIND=tusd, and server g is KIND=gocalbox"},
		{"server s KIND=sshd\ncell x s engine size=1M\n", "engine measures a server of KIND=gocalbox, and server s is KIND=sshd"},
		{"server t KIND=tusd\ncell x t sftp-put size=1M\n", "sftp-put measures a server of KIND=sshd"},
		{"server t KIND=tusd\ncell x t download size=1M\n", "download measures a server of KIND=gocalbox"},
		{"server t KIND=ftp\n", "KIND must be gocalbox, tusd or sshd"},
		{"server t KIND=tusd\ncell x t tus size=1M chunk=0 resume-at=0.5\n", "resume-at needs chunks"},
		{"server t KIND=tusd\ncell x t tus size=1M fault=kill fault-at=0.5\n", "tus takes no fault"},
		{"server t KIND=tusd\ncell x t tus chunk=1M\n", "tus needs a size"},
		{"server s KIND=sshd\ncell x s sftp-get size=1M files=2\n", "sftp-get takes no files"},
		{"server s KIND=sshd\ncell x s scp-put size=1M transport=https-h2\n", "scp-put takes no transport"},
		{"server s KIND=sshd\ncell x s sftp-put size=1M files=0\n", "files must be a number from 1"},
	} {
		if out, ok := plan(c.matrix); ok || !strings.Contains(out, c.want) {
			t.Errorf("%q: %s, want %q", c.matrix, out, c.want)
		}
	}
}

// server.sh refuses the settings a baseline would ignore, and what its
// server can't start without; it never crashes an sshd.
func TestServerShRefusesWhatABaselineCantUse(t *testing.T) {
	needBash(t)
	dir := benchDir(t)
	bin, env := fakeBaselines(t)
	key := "AUTHORIZED_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl client"
	for _, c := range []struct {
		env  []string
		want string
	}{
		{[]string{"KIND=ftp"}, "KIND must be gocalbox, tusd or sshd"},
		{[]string{"KIND=tusd", "BUILD_TAGS=bench"}, "BUILD_TAGS is for gocalbox"},
		{[]string{"KIND=sshd", "SERVER_REV=HEAD", key}, "SERVER_REV is for gocalbox"},
		{[]string{"KIND=sshd", "SERVER_FLAGS=-x", key}, "SERVER_FLAGS is for gocalbox"},
		{[]string{"KIND=tusd", "LOAD_USERS=2"}, "LOAD_USERS is for gocalbox"},
		{[]string{"KIND=tusd", "GOCALBOX_BENCH_PART_SIZE=16M"}, "are for gocalbox"},
		{[]string{"KIND=tusd", "TUSD=" + filepath.Join(bin, "missing")}, "no tusd at"},
		{[]string{"KIND=sshd", "SSHD=sshd", key}, "set SSHD to its absolute path"},
		{[]string{"KIND=sshd"}, "needs AUTHORIZED_KEY"},
		{[]string{"KIND=sshd", "AUTHORIZED_KEY=two\nlines"}, "needs AUTHORIZED_KEY"},
	} {
		if out, ok := script(t, "server.sh", bin, append(append(env, "BENCH_DIR="+dir, "PORT=18395", "BIND=127.0.0.1"), c.env...)...); ok || !strings.Contains(out, c.want) {
			t.Errorf("%q: %s, want %q", c.env, out, c.want)
		}
	}
	// A tusd without the flags the scripts give it.
	write(t, filepath.Join(bin, "oldtusd"), "#!/bin/sh\necho 'Usage of tusd: -dir string'\n")
	os.Chmod(filepath.Join(bin, "oldtusd"), 0o755)
	if out, ok := script(t, "server.sh", bin, append(env, "BENCH_DIR="+dir, "PORT=18395", "BIND=127.0.0.1", "KIND=tusd", "TUSD=oldtusd")...); ok ||
		!strings.Contains(out, "this tusd has no -host flag") {
		t.Errorf("an old tusd: %s", out)
	}
	write(t, filepath.Join(dir, "server", "kind"), "sshd\n")
	write(t, filepath.Join(dir, "server", "ready"), "1\n")
	write(t, filepath.Join(dir, "server", "server.pid"), strconv.Itoa(os.Getpid())+" "+startOf(t, os.Getpid())+"\n")
	if out, ok := scriptArgs(t, []string{"server.sh", "crash"}, "", "BENCH_DIR="+dir); ok || !strings.Contains(out, "doesn't crash an sshd") {
		t.Errorf("crash of an sshd: %s", out)
	}
}

// startOf is when process pid started, as server.sh records it.
func startOf(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	return strings.Fields(s[strings.LastIndex(s, ") ")+2:])[19]
}

// A baseline's transfer that stored or fetched other bytes is marked in its
// row and its outcome, and one whose command failed has 000.
func TestASessionMarksTheBaselinesWrongTransfers(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	bin, env := fakeBaselines(t)
	matrix := filepath.Join(t.TempDir(), "m.txt")
	run := func(mode string, cells string) map[string][]string {
		t.Helper()
		dir := benchDir(t)
		write(t, matrix, "server tusd KIND=tusd\nserver ssh KIND=sshd\n"+cells)
		out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, append(env, mode, "BENCH_DIR="+dir, "PORT=18396", "REPS=1",
			"WARMUP=1", "ROUNDS=1", "DROP_CACHES=0", "IPERF=0", "SERVER_SSH=", "SERVER_HOST=", "CELLS=")...)
		if !ok {
			t.Fatalf("session.sh: %s", out)
		}
		got := map[string][]string{}
		header := strings.Split(load.Header, ",")
		for _, line := range strings.Split(strings.TrimSpace(output(t, out, "results")), "\n")[1:] {
			row := strings.Split(line, ",")
			got[row[2]+" "+row[6]] = []string{row[slices.Index(header, "http_code")]}
		}
		for _, line := range strings.Split(strings.TrimSpace(output(t, out, "order")), "\n")[1:] {
			f := strings.Split(line, ",")
			got[f[2]+" "+f[3]] = append(got[f[2]+" "+f[3]], f[7])
		}
		return got
	}
	env = append(env, "FAKE_TUSD_CORRUPT=1")
	got := run("FAKE_SSH_MODE=corrupt", `cell t  tusd tus size=64K
cell sp ssh sftp-put size=64K files=2
cell sc ssh scp-put size=64K
cell sg ssh sftp-get size=64K
`)
	want := map[string][]string{
		"t 0": {"201 wrong_file", ""}, "sp 0": {"201 wrong_file", ""}, "sc 0": {"201 wrong_file", ""},
		"sg 0": {"200 wrong_file", "got other bytes"}, "sg 1": {"200 wrong_file", "the file placed for it isn't the source's bytes"},
	}
	for run, w := range want {
		g := got[run]
		if len(g) != 2 || g[0] != w[0] || w[1] != "" && g[1] != w[1] || w[1] == "" && !strings.Contains(g[1], "differ from the source's") {
			t.Errorf("%s: %q, want %q", run, g, w)
		}
	}
	env = append(env[:len(env)-1], "FAKE_TUSD_EXTRA=1")
	got = run("FAKE_SSH_MODE=fail", "cell t tusd tus size=64K\ncell sp ssh sftp-put size=64K\ncell sc ssh scp-put size=64K\n")
	for run, w := range map[string][]string{"sp 1": {"000", "sftp failed"}, "sc 1": {"000", "scp failed"},
		"t 1": {"201 wrong_file", "tusd's folder holds 2 files; not the one uploaded"}} {
		if g := got[run]; fmt.Sprint(g) != fmt.Sprint(w) {
			t.Errorf("%s: %q, want %q", run, g, w)
		}
	}
}

// A server whose run.env names another kind than the matrix, as an older
// server.sh on the server would, is refused.
func TestASessionRefusesAServerOfAnotherKind(t *testing.T) {
	sessionTools(t)
	keepResults(t)
	bin, _ := fakeRemote(t)
	client, server := benchDir(t), benchDir(t)
	repo := t.TempDir()
	safe, _ := os.ReadFile("safe.sh")
	write(t, filepath.Join(repo, "bench", "lib", "safe.sh"), string(safe))
	write(t, filepath.Join(repo, "bench", "server.sh"), `#!/bin/bash
# An older bench/server.sh, which knows no KIND.
[ "${1:-}" = stop ] && exit 0
W=$BENCH_DIR/server
mkdir -p "$W/root"
printf 'SRV_COMMIT=old\nSRV_DIRTY=0\nSRV_SCHEME=https\nSRV_CA=/nonexistent\nSRV_ROOT=%s\n' "$W/root" > "$W/run.env"
echo $$ > "$W/ready"
sleep 30
`)
	matrix := filepath.Join(t.TempDir(), "m.txt")
	write(t, matrix, "server t KIND=tusd\ncell x t tus size=64K\n")
	out, ok := scriptArgs(t, []string{"session.sh", matrix}, bin, "BENCH_DIR="+client, "SERVER_SSH=bench@server", "SERVER_HOST=localhost",
		"SERVER_BENCH="+server, "SERVER_REPO="+repo, "PORT=18398", "REPS=1", "WARMUP=0", "DROP_CACHES=0", "IPERF=0", "CELLS=")
	if ok || !strings.Contains(out, "server t is gocalbox, not tusd") {
		t.Errorf("session.sh: %s", out)
	}
}

// tree_usage counts a tree's processes once each: the CPU of those running
// and of those reaped, and the sum of the peak memory of those below the
// first, which is the subreaper.
func TestTreeUsageCountsTheWholeTree(t *testing.T) {
	needBash(t)
	b, err := os.ReadFile(filepath.Join("..", "server.sh"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "tree_usage() {")
	j := strings.Index(src[i:], "\n}\n")
	fn := src[i : i+j+3]
	// A parent that has reaped a busy child, with two children asleep.
	tree := exec.Command("bash", "-c", `(i=0; while [ $i -lt 200000 ]; do i=$((i + 1)); done); sleep 30 & sleep 30 & echo ready; wait`)
	stdout, _ := tree.StdoutPipe()
	if err := tree.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		exec.Command("pkill", "-P", strconv.Itoa(tree.Process.Pid)).Run()
		tree.Process.Kill()
		tree.Wait()
	}()
	buf := make([]byte, 6)
	io.ReadFull(stdout, buf)
	time.Sleep(200 * time.Millisecond)
	out, err := exec.Command("bash", "-c", fn+"\ntree_usage "+strconv.Itoa(tree.Process.Pid)).Output()
	if err != nil {
		t.Fatal(err)
	}
	var ticks, rss int
	fmt.Sscan(string(out), &ticks, &rss)
	field := func(pid int, name string) int {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		for _, l := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, name+":"); ok {
				n, _ := strconv.Atoi(strings.Fields(v)[0])
				return n
			}
		}
		return 0
	}
	want := 0
	kids, _ := exec.Command("pgrep", "-P", strconv.Itoa(tree.Process.Pid)).Output()
	n := 0
	for _, k := range strings.Fields(string(kids)) {
		pid, _ := strconv.Atoi(k)
		want += field(pid, "VmHWM")
		n++
	}
	if n != 2 || want == 0 || rss != want {
		t.Errorf("%d children; peak RSS %d kB, want %d", n, rss, want)
	}
	stat, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", tree.Process.Pid))
	f := strings.Fields(string(stat)[strings.LastIndex(string(stat), ") ")+2:])
	reaped, _ := strconv.Atoi(f[13])
	if reaped == 0 || ticks < reaped {
		t.Errorf("%d ticks, though the busy child alone took %d", ticks, reaped)
	}
}

// sshd's CPU, read over its processes, never falls from one sample to the
// next, though a scan can miss a child: here every session loses one
// child's time, which a running maximum keeps from showing as a fall.
func TestSshdsSamplesNeverFall(t *testing.T) {
	serverTools(t)
	keepResults(t)
	bin, env := fakeBaselines(t)
	dir := benchDir(t)
	key := "AUTHORIZED_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl client"
	cmd, out := serverSh(t, bin, append(env, "FAKE_SSHD_DIP=1", "KIND=sshd", key, "BENCH_DIR="+dir, "PORT=18399", "BIND=127.0.0.1",
		"ENV_DIR="+filepath.Join(dir, "server", "envs"))...)
	waitFor(t, "the server", func() bool { return exists(filepath.Join(dir, "server", "ready")) })
	for range 4 {
		c, err := net.Dial("tcp", "127.0.0.1:18399")
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("x"))
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasSuffix(string(b), "done\n") {
			t.Fatalf("the fake sshd answered %q", b)
		}
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	if o, ok := scriptArgs(t, []string{"server.sh", "stop"}, "", "BENCH_DIR="+dir); !ok {
		t.Fatalf("stop: %s\n%s", o, out())
	}
	<-done
	b, _ := os.ReadFile(filepath.Join(dir, "server", "samples.csv"))
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	last := 0.0
	for _, line := range lines {
		cpu, _ := strconv.ParseFloat(strings.Split(line, ",")[1], 64)
		if cpu < last {
			t.Errorf("sshd's CPU fell from %g to %g", last, cpu)
		}
		last = cpu
	}
	if len(lines) < 10 || last < 0.1 {
		t.Errorf("%d samples, ending at %g CPU seconds", len(lines), last)
	}
}
