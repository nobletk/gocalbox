"""Tests of bench/charts.py: python3 -m unittest discover -s bench -p 'test_charts.py'"""

import csv
import hashlib
import io
import os
import sys
import tempfile
import unittest

import numpy as np
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import charts  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results")

COLUMNS = ["commit", "dirty", "scenario", "size_bytes", "files", "concurrency", "rep", "seconds", "mib_per_s",
           "durable_upper_seconds", "server_cpu_s", "http_code", "transport", "part_p50_ms", "part_p99_ms",
           "complete_p50_ms", "complete_max_ms", "retried", "resent_bytes", "user_min_mib_s", "user_max_mib_s",
           "client_cpu_s", "resumed", "resume_p50_s", "resume_max_s", "stalled_s", "started_unix"]

ENV = """host: test
iperf3 at the start, Mbit/s: to the server 940, from the server 900
iperf3 at the end, Mbit/s: to the server 960, from the server 920
"""


def write_session(folder, name, rows, order=None, env=ENV, seeks=None):
    with open(os.path.join(folder, name + ".csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({c: r.get(c, "") for c in COLUMNS})
    if order is not None:
        with open(os.path.join(folder, name + "-order.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["seq", "server", "cell", "rep", "round", "t0", "t1", "outcome"])
            for seq, (cell, rep) in enumerate(order, 1):
                w.writerow([seq, "default", cell, rep, 1, 0, 0, "ok"])
    if env is not None:
        with open(os.path.join(folder, name + "-env.txt"), "w") as f:
            f.write(env)
    if seeks is not None:
        with open(os.path.join(folder, name + "-seeks.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["seq", "cell", "rep", "seek", "offset", "bytes", "http_code", "first_byte_ms", "ms"])
            for s in seeks:
                w.writerow(s)


def row(cell, rep, mib, code="201", **kw):
    r = {"scenario": cell, "rep": str(rep), "mib_per_s": str(mib), "http_code": code, "size_bytes": str(1 << 30),
         "files": "1", "server_cpu_s": "2.0"}
    r.update({k: str(v) for k, v in kw.items()})
    return r


def session1(folder):
    """A small session 1 with every cell its figures read."""
    rows = []
    cells = ([f"x1-{p}-{z}" for p in ("engine-h2", "engine-h1", "single-h2", "single-h1") for z in ("1M", "64M", "1G", "5G")]
             + [f"x1-down-{p}-{z}" for p in ("h2", "h1") for z in ("64M", "1G", "5G")]
             + [f"x1-batch-c{c}" for c in (1, 4, 16)]
             + [f"x2-audit-{m}-{z}" for m in ("default", "parts", "nowait") for z in ("1M", "1G")]
             + [f"x2-staged-{v}-{z}" for v in ("pre", "now") for z in ("64M", "1G")]
             + ["x2-batch-pre-c4", "x2-batch-now-c4"]
             + [f"x3-nvme-{z}" for z in ("1M", "64M", "1G", "5G", "20G", "50G")]
             + [f"x5-{w}-{p}" for w in ("w128", "w256", "w448", "w1m") for p in ("engine", "single")])
    for c in cells:
        for rep in (0, 1, 2, 3):
            rows.append(row(c, rep, 100 + rep, complete_p50_ms=20 + rep))
    for u in (1, 2, 4, 8, 16):
        for rep in (0, 1, 2, 3):
            rows.append(row(f"x6-users-{u}", rep, 100 * u, user_min_mib_s=8, user_max_mib_s=10,
                            retried="503x100" if u == 16 else ""))
    write_session(folder, "session-1-loopback-20261021-113623", rows, env="no link here\n")


class Helpers(unittest.TestCase):
    def test_refusals_count_only_503(self):
        self.assertEqual(charts.refusals("503x2737"), 2737)
        self.assertEqual(charts.refusals("429x3 503x12"), 12)
        self.assertEqual(charts.refusals("000x4 409x1 503x7"), 7)
        self.assertEqual(charts.refusals("000x16"), 0)
        self.assertEqual(charts.refusals(""), 0)
        self.assertEqual(charts.refusals(None), 0)
        self.assertEqual(charts.refusals("503xabc"), 0)
        self.assertEqual(charts.refusals("503x2 503x3"), 5)

    def test_summary_is_the_median_and_quartiles(self):
        self.assertIsNone(charts.summary([]))
        self.assertEqual(charts.summary([4.0]), (4.0, 4.0, 4.0))
        self.assertEqual(charts.summary([1, 2, 3, 4, 5]), (3.0, 2.0, 4.0))

    def test_num(self):
        self.assertIsNone(charts.num(""))
        self.assertIsNone(charts.num(None))
        self.assertIsNone(charts.num("x"))
        self.assertEqual(charts.num("1.5"), 1.5)

    def test_size_label(self):
        self.assertEqual(charts.size_label("x1-engine-h2-64M"), "64 MiB")
        self.assertEqual(charts.size_label("x-5G"), "5 GiB")


class Loading(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_warm_ups_and_failed_runs_are_left_out(self):
        write_session(self.dir, "s", [row("c", 0, 1), row("c", 1, 2), row("c", 2, 3, code="500"),
                                      row("c", 3, 4, code="206"), row("c", 4, 5, code="")])
        s = charts.load(self.dir, "s", "k", "label")
        self.assertEqual([r["mib_per_s"] for r in s.rows], ["2", "4"])
        self.assertEqual(s.dropped, 2)
        self.assertEqual(s.values("c", "mib_per_s"), [2.0, 4.0])
        self.assertEqual(s.values("c", "mib_per_s", scale=2), [4.0, 8.0])

    def test_a_missing_session_is_none(self):
        self.assertIsNone(charts.load(self.dir, "nothing", "k", "l"))

    def test_runs_set_apart_by_their_place_in_the_order(self):
        name = "session-1-loopback-20261026-131827"
        rows = [row("a", rep, rep) for rep in range(4)] + [row("b", rep, 10 + rep) for rep in range(4)]
        order = [("a", "0"), ("b", "0"), ("a", "1"), ("b", "1"), ("a", "2"), ("b", "2"), ("a", "3"), ("b", "3")]
        # The rule sets apart from the 54th run on; this order has 8, so pad it.
        order = [("pad", str(i)) for i in range(50)] + order
        write_session(self.dir, name, rows, order=order)
        s = charts.load(self.dir, name, "k", "l")
        # a1 is the 53rd run and stays; b1 is the 54th and goes, with all after it.
        self.assertEqual(s.values("a", "mib_per_s"), [1.0])
        self.assertEqual(s.values("b", "mib_per_s"), [])
        self.assertEqual(s.excluded, 5)

    def test_seeks_leave_out_warm_ups_and_failures(self):
        write_session(self.dir, "s", [row("x8-seek-h1", 1, 1)], seeks=[
            [1, "x8-seek-h1", 0, 1, 0, 1, 206, 0.5, 9], [2, "x8-seek-h1", 1, 1, 0, 1, 206, 0.6, 10],
            [2, "x8-seek-h1", 1, 2, 0, 1, 500, 0.7, 11]])
        s = charts.load(self.dir, "s", "k", "l")
        self.assertEqual([r["ms"] for r in s.seeks], ["10"])

    def test_the_link_rate_is_the_mean_of_start_and_end(self):
        write_session(self.dir, "s", [row("c", 1, 1)])
        s = charts.load(self.dir, "s", "k", "l")
        self.assertAlmostEqual(s.link("to"), 950e6 / 8 / (1 << 20))
        self.assertAlmostEqual(s.link("from"), 910e6 / 8 / (1 << 20))
        write_session(self.dir, "t", [row("c", 1, 1)], env="nothing")
        self.assertIsNone(charts.load(self.dir, "t", "k", "l").link())
        write_session(self.dir, "u", [row("c", 1, 1)], env=None)
        self.assertIsNone(charts.load(self.dir, "u", "k", "l").link())


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = charts.main(list(args))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


class Drawing(unittest.TestCase):
    def setUp(self):
        self.results = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()
        session1(self.results)

    def test_figures_whose_sessions_are_there_are_drawn_and_the_rest_skipped(self):
        code, out, _ = run("--results", self.results, "--out", self.out)
        self.assertEqual(code, 0)
        drawn = {n for n, needs, _, _ in charts.FIGURES if needs == ["s1"]}
        self.assertEqual(len(drawn), 5)
        for n in drawn:
            for fmt in ("pdf", "png"):
                self.assertTrue(os.path.getsize(os.path.join(self.out, f"{n}.{fmt}")) > 1000, n)
        others = [n for n, *_ in charts.FIGURES if n not in drawn]
        for n in others:
            self.assertFalse(os.path.exists(os.path.join(self.out, f"{n}.pdf")), n)
            self.assertIn(f"{n}: skipped", out)
        self.assertIn(f"5 figures in {self.out}, {len(others)} skipped", out)
        with open(os.path.join(self.out, "index.md")) as f:
            index = f.read()
        for n in drawn:
            self.assertIn(f"## {n}", index)
        self.assertIn("Sources: `session-1-loopback-20261021-113623`.", index)
        self.assertNotIn("fig06", index)

    def test_the_same_results_draw_the_same_bytes(self):
        run("--results", self.results, "--out", self.out, "--only", "fig01-x1-uploads")
        first = {f: digest(os.path.join(self.out, f)) for f in os.listdir(self.out)}
        run("--results", self.results, "--out", self.out, "--only", "fig01-x1-uploads")
        self.assertEqual(first, {f: digest(os.path.join(self.out, f)) for f in os.listdir(self.out)})

    def test_only_and_formats(self):
        code, out, _ = run("--results", self.results, "--out", self.out, "--only", "fig05-x3-complete", "--formats", "svg")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(self.out)), ["fig05-x3-complete.svg"])
        self.assertIn("1 figures", out)

    def test_bad_arguments_are_refused(self):
        self.assertEqual(run("--results", self.results, "--out", self.out, "--formats", "jpg")[0], 2)
        self.assertEqual(run("--results", self.results, "--out", self.out, "--only", "nope")[0], 2)
        self.assertEqual(run("--results", os.path.join(self.results, "missing"), "--out", self.out)[0], 2)
        self.assertEqual(os.listdir(self.out), [])

    def test_the_results_are_only_read(self):
        before = {f: digest(os.path.join(self.results, f)) for f in os.listdir(self.results)}
        run("--results", self.results, "--out", self.out)
        self.assertEqual(before, {f: digest(os.path.join(self.results, f)) for f in os.listdir(self.results)})


class Robustness(unittest.TestCase):
    def setUp(self):
        self.results = tempfile.mkdtemp()
        self.out = tempfile.mkdtemp()

    def test_a_set_apart_session_without_its_order_isnt_used(self):
        name = "session-1-loopback-20261026-131827"
        write_session(self.results, name, [row("x6-users-1", r, 100) for r in range(1, 3)])
        with self.assertRaises(ValueError):
            charts.load(self.results, name, "k", "l")
        code, out, _ = run("--results", self.results, "--out", self.out)
        self.assertEqual(code, 0)
        self.assertIn(f"{name}: not used:", out)

    def test_a_run_missing_from_the_order_stops_it_too(self):
        name = "session-1-loopback-20261026-131827"
        write_session(self.results, name, [row("a", 1, 1), row("a", 2, 2)], order=[("a", "1")])
        with self.assertRaises(ValueError):
            charts.load(self.results, name, "k", "l")

    def test_empty_values_are_left_out(self):
        session1(self.results)
        rows = []
        for key, name in (("x6lan", "session-2-lan-20261022-160558"), ("x6loop", "session-1-loopback-20261026-131827")):
            rows = [row("x6-users-1", 1, ""), row("x6-users-1", 2, 50, user_min_mib_s=1, user_max_mib_s=""),
                    row("x6-users-1", 3, 60, user_min_mib_s=1, user_max_mib_s=0), row("x6-users-1", 4, 70, user_min_mib_s=1, user_max_mib_s=2)]
            order = [("x6-users-1", str(r)) for r in range(1, 5)] if key == "x6loop" else None
            write_session(self.results, name, rows, order=order)
        write_session(self.results, "session-2-lan-20261021-134011",
                      [row("x6-users-1", 1, 10, user_min_mib_s=1, user_max_mib_s=1)])
        code, out, _ = run("--results", self.results, "--out", self.out, "--only", "fig10-x6-throughput,fig11-x6-fairness")
        self.assertEqual(code, 0, out)
        self.assertIn("2 figures in", out)

    def test_a_figure_whose_cells_are_all_missing_isnt_drawn(self):
        for name, _ in charts.SESSIONS.values():
            write_session(self.results, name, [row("nothing", 1, 1)], order=[("nothing", "1")])
        code, out, _ = run("--results", self.results, "--out", self.out)
        self.assertEqual(code, 0)
        self.assertIn(f"0 figures in {self.out}, {len(charts.FIGURES)} skipped", out)
        self.assertEqual(os.listdir(self.out), ["index.md"])

    def test_empty_seek_times_are_left_out(self):
        write_session(self.results, "s", [row("x8-seek-h1", 1, 1)], seeks=[
            [1, "x8-seek-h1", 1, 1, 0, 1, 206, "", 9], [1, "x8-seek-h1", 1, 2, 0, 1, 206, 0.5, ""]])
        s = charts.load(self.results, "s", "k", "l")
        self.assertEqual(s.seek_times("x8-seek-h1", "first_byte_ms"), [0.5])
        self.assertEqual(s.seek_times("x8-seek-h1", "ms"), [9.0])

    def test_svg_is_reproducible_too(self):
        session1(self.results)
        run("--results", self.results, "--out", self.out, "--only", "fig02-x1-downloads-batch", "--formats", "svg")
        first = digest(os.path.join(self.out, "fig02-x1-downloads-batch.svg"))
        run("--results", self.results, "--out", self.out, "--only", "fig02-x1-downloads-batch", "--formats", "svg")
        self.assertEqual(first, digest(os.path.join(self.out, "fig02-x1-downloads-batch.svg")))

    def test_a_full_run_drops_old_formats_but_keeps_figures_it_didnt_draw(self):
        session1(self.results)
        for f in ("fig06-x4-parallel.pdf", "fig01-x1-uploads.svg", "mine.txt"):
            open(os.path.join(self.out, f), "w").close()
        run("--results", self.results, "--out", self.out)
        left = set(os.listdir(self.out))
        self.assertNotIn("fig01-x1-uploads.svg", left)
        self.assertIn("fig01-x1-uploads.pdf", left)
        self.assertIn("fig06-x4-parallel.pdf", left)
        self.assertIn("mine.txt", left)
        with open(os.path.join(self.out, "index.md")) as f:
            index = f.read()
        self.assertIn("## fig06-x4-parallel (from an earlier run)", index)
        caption = next(c for n, _, c, _ in charts.FIGURES if n == "fig06-x4-parallel")
        self.assertIn(caption, index)
        self.assertNotIn("fig07-x5-protocol", index)

    def test_a_figure_skipped_for_lack_of_cells_keeps_its_files(self):
        session1(self.results)
        run("--results", self.results, "--out", self.out, "--formats", "png")
        self.assertTrue(os.path.exists(os.path.join(self.out, "fig05-x3-complete.png")))
        rows = [r for r in csv.DictReader(open(os.path.join(self.results, "session-1-loopback-20261021-113623.csv")))
                if not r["scenario"].startswith("x3-")]
        write_session(self.results, "session-1-loopback-20261021-113623", rows, env="x")
        _, out, _ = run("--results", self.results, "--out", self.out, "--formats", "pdf")
        self.assertIn("fig05-x3-complete: skipped, no x3 cells", out)
        self.assertTrue(os.path.exists(os.path.join(self.out, "fig05-x3-complete.png")))
        self.assertFalse(os.path.exists(os.path.join(self.out, "fig01-x1-uploads.png")))
        with open(os.path.join(self.out, "index.md")) as f:
            self.assertIn("## fig05-x3-complete (from an earlier run)", f.read())

    def test_order_files_that_cant_be_read_make_the_session_unused(self):
        name = "session-1-loopback-20261026-131827"
        for bad in ("seq,server,rep,round\n1,default,1,1\n", "seq,server,cell,rep,round,t0,t1,outcome\n1,default\n"):
            write_session(self.results, name, [row("c", 1, 1)])
            with open(os.path.join(self.results, name + "-order.csv"), "w") as f:
                f.write(bad)
            with self.assertRaises(ValueError):
                charts.load(self.results, name, "k", "l")
            code, out, _ = run("--results", self.results, "--out", self.out)
            self.assertEqual(code, 0)
            self.assertIn(f"{name}: not used:", out)

    def test_an_order_file_matters_only_where_runs_are_set_apart(self):
        write_session(self.results, "session-2-lan-20261021-134011", [row("c", 1, 1)], order=[("c", "1")])
        with open(os.path.join(self.results, "session-2-lan-20261021-134011-order.csv"), "a") as f:
            f.write(",default,c,2,1,0,0,ok\n")
        s = charts.load(self.results, "session-2-lan-20261021-134011", "k", "l")
        self.assertEqual(len(s.rows), 1)
        name = "session-1-loopback-20261026-131827"
        write_session(self.results, name, [row("c", 1, 1)], order=[("c", "1")])
        with open(os.path.join(self.results, name + "-order.csv"), "a") as f:
            f.write(",default,c,2,1,0,0,ok\n")
        with self.assertRaises(ValueError):
            charts.load(self.results, name, "k", "l")

    def test_a_session_not_used_is_named_so(self):
        session1(self.results)
        write_session(self.results, "session-1-loopback-20261026-131827", [row("x6-users-1", 1, 1)])
        _, out, _ = run("--results", self.results, "--out", self.out)
        self.assertIn("fig10-x6-throughput: skipped, not used: session-1-loopback-20261026-131827; "
                      "missing: session-2-lan-20261021-134011, session-2-lan-20261022-160558", out)
        self.assertIn("fig06-x4-parallel: skipped, missing: session-2-lan-20261021-134011", out)

    def test_a_partial_run_keeps_the_index_and_the_rest(self):
        session1(self.results)
        run("--results", self.results, "--out", self.out)
        with open(os.path.join(self.out, "index.md")) as f:
            index = f.read()
        before = set(os.listdir(self.out))
        _, out, _ = run("--results", self.results, "--out", self.out, "--only", "fig05-x3-complete")
        self.assertIn("index.md left as it was", out)
        self.assertEqual(before, set(os.listdir(self.out)))
        with open(os.path.join(self.out, "index.md")) as f:
            self.assertEqual(index, f.read())

    def test_the_index_names_the_formats(self):
        session1(self.results)
        run("--results", self.results, "--out", self.out, "--formats", "png")
        with open(os.path.join(self.out, "index.md")) as f:
            self.assertIn("as PNG.", f.read())


# --- the figures against the real results -------------------------------------

def raw(name, cell, column, transform=None):
    """A cell's values read straight from the CSV, apart from charts.py:
    measured runs that answered as they should, without the runs set apart."""
    seqs = {}
    order = os.path.join(RESULTS, name + "-order.csv")
    if os.path.exists(order):
        with open(order, newline="") as f:
            for r in csv.DictReader(f):
                seqs[(r["cell"], r["rep"])] = int(r["seq"])
    out = []
    with open(os.path.join(RESULTS, name + ".csv"), newline="") as f:
        for r in csv.DictReader(f):
            if r["scenario"] != cell or r["rep"] == "0" or r["http_code"] not in ("200", "201", "206"):
                continue
            if name == "session-1-loopback-20261026-131827" and seqs[(cell, r["rep"])] >= 54:
                continue
            v = transform(r) if transform else (float(r[column]) if r[column] else None)
            if v is not None:
                out.append(v)
    return out


def med(name, cell, column="mib_per_s", transform=None):
    v = raw(name, cell, column, transform)
    return float(np.median(v)) if v else None


def bar_heights(fig, label):
    from matplotlib.container import BarContainer
    out = []
    for ax in fig.axes:
        for c in ax.containers:
            if isinstance(c, BarContainer) and c.get_label() == label:
                out += [p.get_height() for p in c.patches]
    return out


def whiskers(fig, label):
    """(low, high) of each bar's interquartile whisker, in bar order."""
    from matplotlib.container import BarContainer
    out = []
    for ax in fig.axes:
        for c in ax.containers:
            if isinstance(c, BarContainer) and c.get_label() == label:
                segs = c.errorbar.lines[2][0].get_segments()
                out += [(min(seg[0][1], seg[1][1]), max(seg[0][1], seg[1][1])) for seg in segs]
    return out


def quartiles(name, cell, column="mib_per_s"):
    q1, q3 = np.percentile(raw(name, cell, column), [25, 75])
    return float(q1), float(q3)


def line(ax, label):
    for ln in ax.get_lines():
        if ln.get_label() == label:
            return ln
    for c in ax.containers:
        if c.__class__.__name__ == "ErrorbarContainer" and c.get_label() == label:
            return c.lines[0]
    raise AssertionError(f"no line {label!r}")


def hline_ys(ax):
    ys = [ln.get_ydata()[0] for ln in ax.get_lines() if len(set(ln.get_ydata())) == 1]
    for c in ax.collections:
        if c.__class__.__name__ == "LineCollection":
            ys += [seg[0][1] for seg in c.get_segments()]
    return ys


S1, S2, S3 = "session-1-loopback-20261021-113623", "session-2-lan-20261021-134011", "session-2-lan-20261022-003044"
S3B, X13 = "session-3b-windows-20261022-180157", "session-13-swap-20261022-152333"
X6LAN, X6LOOP = "session-2-lan-20261022-160558", "session-1-loopback-20261026-131827"
X7LAN, X7WIFI = "session-2-lan-20261023-113117", "session-2-lan-20261023-124658"


@unittest.skipUnless(os.path.exists(os.path.join(RESULTS, X6LOOP + ".csv")), "the repository's results aren't here")
class TheRealResults(unittest.TestCase):
    """Each figure draws the cells and columns it says, and its numbers agree
    with the session reports."""

    @classmethod
    def setUpClass(cls):
        charts.style()
        cls.S = {k: charts.load(RESULTS, n, k, lab) for k, (n, lab) in charts.SESSIONS.items()}

    def draw(self, name):
        fn = next(f for n, _, _, f in charts.FIGURES if n == name)
        fig, _ = fn(self.S)
        self.addCleanup(lambda: charts.plt.close(fig))
        return fig

    def assertSeries(self, got, want):
        self.assertEqual(len(got), len(want))
        for g, w in zip(got, want):
            self.assertAlmostEqual(g, w, places=6)

    def test_the_reports_numbers(self):
        self.assertEqual(self.S["x6loop"].excluded, 13)
        self.assertEqual(round(med(X6LOOP, "x6-users-16")), 1301)
        self.assertEqual(round(med(X6LOOP, "x6-users-1")), 486)
        self.assertEqual(round(med(S1, "x6-users-16")), 1322)
        before = [charts.refusals(r) for r in raw(S1, "x6-users-16", None, lambda r: r["retried"])]
        self.assertEqual((min(before), max(before)), (2171, 2768))
        self.assertAlmostEqual(self.S["s2"].link("to"), 940e6 / 8 / (1 << 20), places=3)

    def test_whiskers_span_the_quartiles(self):
        fig = self.draw("fig01-x1-uploads")
        got = whiskers(fig, "engine, HTTP/2")
        want = [quartiles(S1, f"x1-engine-h2-{z}") for z in ("1M", "64M", "1G", "5G")]
        for g, w in zip(got, want):
            self.assertAlmostEqual(g[0], w[0], places=6)
            self.assertAlmostEqual(g[1], w[1], places=6)
        self.assertEqual(len(got), 4)

    def test_fig01(self):
        fig = self.draw("fig01-x1-uploads")
        for key, label in [("engine-h2", "engine, HTTP/2"), ("engine-h1", "engine, HTTP/1.1"),
                           ("single-h2", "single request, HTTP/2"), ("single-h1", "single request, HTTP/1.1")]:
            self.assertSeries(bar_heights(fig, label), [med(S1, f"x1-{key}-{z}") for z in ("1M", "64M", "1G", "5G")])

    def test_fig02(self):
        fig = self.draw("fig02-x1-downloads-batch")
        self.assertSeries(bar_heights(fig, "HTTP/2"), [med(S1, f"x1-down-h2-{z}") for z in ("64M", "1G", "5G")])
        self.assertSeries(bar_heights(fig, "HTTP/1.1"), [med(S1, f"x1-down-h1-{z}") for z in ("64M", "1G", "5G")])
        self.assertSeries(bar_heights(fig, "batch"), [med(S1, f"x1-batch-c{c}") for c in (1, 4, 16)])

    def test_fig03(self):
        fig = self.draw("fig03-x1-cpu")
        per_gib = lambda r: float(r["server_cpu_s"]) / (int(r["size_bytes"]) * int(r["files"]) / (1 << 30))
        self.assertSeries(bar_heights(fig, "single, HTTP/2"), [med(S1, f"x1-single-h2-{z}", transform=per_gib) for z in ("1G", "5G")])
        self.assertSeries(bar_heights(fig, "engine, HTTP/1.1"), [med(S1, f"x1-engine-h1-{z}", transform=per_gib) for z in ("1G", "5G")])

    def test_fig04(self):
        fig = self.draw("fig04-x2-guarantees")
        self.assertSeries(bar_heights(fig, "every part audited"), [med(S1, f"x2-audit-parts-{z}") for z in ("1M", "1G")])
        self.assertSeries(bar_heights(fig, "no audit wait"), [med(S1, f"x2-audit-nowait-{z}") for z in ("1M", "1G")])
        self.assertSeries(bar_heights(fig, "before M6"), [med(S1, c) for c in ("x2-staged-pre-64M", "x2-staged-pre-1G", "x2-batch-pre-c4")])
        self.assertSeries(bar_heights(fig, "after M6"), [med(S1, c) for c in ("x2-staged-now-64M", "x2-staged-now-1G", "x2-batch-now-c4")])

    def test_a_figures_bar_series_differ_in_colour(self):
        from matplotlib.colors import to_hex
        from matplotlib.container import BarContainer
        for name, _, _, _ in charts.FIGURES:
            with self.subTest(name):
                fig = self.draw(name)
                looks = {}
                for ax in fig.axes:
                    for c in ax.containers:
                        if isinstance(c, BarContainer) and c.patches:
                            looks.setdefault(c.get_label(), set()).add(
                                (to_hex(c.patches[0].get_facecolor()), c.patches[0].get_hatch()))
                for lab, l in looks.items():
                    self.assertEqual(len(l), 1, lab)
                seen = [next(iter(l)) for l in looks.values()]
                self.assertEqual(len(seen), len(set(seen)), sorted(looks))

    def test_fig05(self):
        fig = self.draw("fig05-x3-complete")
        self.assertSeries(fig.axes[0].get_lines()[0].get_ydata(),
                          [med(S1, f"x3-nvme-{z}", "complete_p50_ms") for z in ("1M", "64M", "1G", "5G", "20G", "50G")])

    def test_fig06(self):
        fig = self.draw("fig06-x4-parallel")
        for ax, name, key in zip(fig.axes, (S2, S3), ("s2", "s3")):
            for p in (8, 16, 64):
                self.assertSeries(line(ax, f"{p} MiB parts").get_ydata(), [med(name, f"x4-p{p}-par{n}-1G") for n in (1, 2, 4, 8)])
            self.assertIn(round(self.S[key].link("to"), 6), [round(y, 6) for y in hline_ys(ax)])

    def test_fig07(self):
        fig = self.draw("fig07-x5-protocol")
        want = []
        for name in (S2, S3):
            want += [med(name, f"x5-{g}-h2") for g in ("engine", "single", "down")]
        self.assertSeries(bar_heights(fig, "HTTP/2"), want)
        for ax, key in zip(fig.axes, ("s2", "s3")):
            spans = {}
            for c in ax.collections:
                if c.__class__.__name__ == "LineCollection":
                    for seg in c.get_segments():
                        spans[(round(seg[0][0], 3), round(seg[1][0], 3))] = seg[0][1]
            self.assertAlmostEqual(spans[(-0.5, 1.5)], self.S[key].link("to"), places=6)
            self.assertAlmostEqual(spans[(1.5, 2.5)], self.S[key].link("from"), places=6)

    def test_fig08(self):
        fig = self.draw("fig08-x5-windows")
        self.assertEqual([ax.get_title(loc="left") for ax in fig.axes], ["(a) loopback", "(b) LAN", "(c) Wi-Fi"])
        want = []
        for name in (S1, S2, S3):
            want += [med(name, f"x5-{w}-engine") for w in ("w128", "w256", "w448", "w1m")]
        self.assertSeries(bar_heights(fig, "engine"), want)
        want = []
        for name in (S1, S2, S3):
            want += [med(name, f"x5-{w}-single") for w in ("w128", "w256", "w448", "w1m")]
        self.assertSeries(bar_heights(fig, "single request"), want)

    def test_fig09(self):
        fig = self.draw("fig09-x13-swap")
        cells = ("engine-h2", "engine-h1", "single-h2", "single-h1", "down-h2", "down-h1")
        self.assertSeries(bar_heights(fig, "server PC A (session 2)"), [med(S2, f"x5-{c}") for c in cells])
        self.assertSeries(bar_heights(fig, "server PC B (X13)"), [med(X13, f"x13-{c}") for c in cells])

    def test_fig10(self):
        fig = self.draw("fig10-x6-throughput")
        loop, lan = fig.axes[:2]
        self.assertSeries(line(loop, "before M9").get_ydata(), [med(S1, f"x6-users-{u}") for u in (1, 2, 4, 8, 16)])
        self.assertSeries(line(loop, "after M9").get_ydata(), [med(X6LOOP, f"x6-users-{u}") for u in (1, 2, 4, 8, 16, 24)])
        self.assertSeries(line(lan, "before M9").get_ydata(), [med(S2, f"x6-users-{u}") for u in (1, 4, 16)])
        self.assertSeries(line(lan, "after M9").get_ydata(), [med(X6LAN, f"x6-users-{u}") for u in (1, 4, 16, 24)])
        self.assertEqual(list(line(lan, "after M9").get_xdata()), [1, 4, 16, 24])
        band = [c for c in loop.collections if c.__class__.__name__ in ("PolyCollection", "FillBetweenPolyCollection")][1]
        ys = band.get_paths()[0].vertices[:, 1]
        q = [quartiles(X6LOOP, f"x6-users-{u}") for u in (1, 2, 4, 8, 16, 24)]
        self.assertAlmostEqual(max(ys), max(v[1] for v in q), places=6)
        self.assertAlmostEqual(min(ys), min(v[0] for v in q), places=6)
        self.assertTrue(all(any(abs(y - v[1]) < 1e-6 for y in ys) for v in q))

    def test_fig11(self):
        fig = self.draw("fig11-x6-fairness")
        a, b = fig.axes[:2]
        ratio = lambda r: float(r["user_min_mib_s"]) / float(r["user_max_mib_s"])
        self.assertSeries(line(a, "loopback, before M9").get_ydata(), [med(S1, f"x6-users-{u}", transform=ratio) for u in (1, 2, 4, 8, 16)])
        self.assertAlmostEqual(med(S1, "x6-users-16", transform=ratio), 0.79, places=2)
        c = next(c for c in a.containers if c.__class__.__name__ == "ErrorbarContainer" and c.get_label() == "loopback, after M9")
        segs = c.lines[2][0].get_segments()
        for seg, u in zip(segs, (1, 2, 4, 8, 16, 24)):
            v = raw(X6LOOP, f"x6-users-{u}", None, ratio)
            q1, q3 = np.percentile(v, [25, 75])
            self.assertAlmostEqual(min(seg[0][1], seg[1][1]), q1, places=6)
            self.assertAlmostEqual(max(seg[0][1], seg[1][1]), q3, places=6)
        refused = lambda name, u: med(name, f"x6-users-{u}", transform=lambda r: charts.refusals(r["retried"]))
        got = line(b, "LAN, before M9").get_ydata()
        self.assertEqual([np.isnan(v) for v in got], [False, True, False, True, False, True])
        self.assertSeries([v for v in got if not np.isnan(v)], [refused(S2, u) for u in (1, 4, 16)])
        self.assertSeries([v for v in line(b, "LAN, after M9").get_ydata() if not np.isnan(v)],
                          [refused(X6LAN, u) for u in (1, 4, 16, 24)])
        self.assertGreater(b.get_ylim()[1], 8400 * 1.5)

    def test_fig12(self):
        fig = self.draw("fig12-x7-resume")
        lan, wifi = fig.axes[:2]

        def points(ax, label):
            ys = []
            for c in ax.collections:
                if c.get_label() == label:
                    ys += list(c.get_offsets()[:, 1])
            return sorted(ys)

        def at_share(ax, label, share):
            ys = []
            for c in ax.collections:
                if c.get_label() == label:
                    ys += [y for x, y in c.get_offsets() if abs(x - share) <= 5]
            return sorted(ys)

        self.assertEqual(points(lan, "client stops and resumes"),
                         sorted(sum((raw(X7LAN, f"x7-stop-{p}", "resume_p50_s") for p in (10, 50, 90)), [])))
        for p in (10, 50, 90):
            self.assertEqual(at_share(lan, "server killed and restarted", p), sorted(raw(X7LAN, f"x7-kill-{p}", "resume_p50_s")))
            self.assertEqual(at_share(wifi, "network cut for 10 s", p), sorted(raw(X7WIFI, f"x7-cut-{p}", "resume_p50_s")))

        for ax, name in ((lan, X7LAN), (wifi, X7WIFI)):
            self.assertEqual(points(ax, "server killed and restarted"),
                             sorted(sum((raw(name, f"x7-kill-{p}", "resume_p50_s") for p in (10, 50, 90)), [])))
            self.assertEqual(points(ax, "network cut for 60 s"), sorted(raw(name, "x7-cut-50-60s", "resume_p50_s")))
        self.assertEqual(points(wifi, "client stops and resumes"),
                         sorted(sum((raw(S3, f"x7-stop-{p}", "resume_p50_s") for p in (10, 50, 90)), [])))
        ref = line(lan, "rest of the file at the link's rate, 111.6 MiB/s")
        x, y = ref.get_xdata(), ref.get_ydata()
        self.assertAlmostEqual(np.interp(10, x, y), 5120 * 0.9 / 111.6, places=6)
        ref = line(wifi, "rest of the file at the uploads' own rate before the fault, 99.4 MiB/s")
        self.assertAlmostEqual(np.interp(50, ref.get_xdata(), ref.get_ydata()), 5120 * 0.5 / 99.4, places=6)

    def test_fig13(self):
        fig = self.draw("fig13-x8-seeks")
        a, b = fig.axes[:2]
        first = sorted(float(r["first_byte_ms"]) for r in self.S["x7lan"].seeks if r["cell"] == "x8-seek-h2")
        self.assertEqual(len(first), 1000)
        self.assertSeries(line(a, "LAN, HTTP/2").get_xdata(), first)
        self.assertAlmostEqual(float(np.median(first)), 0.47, places=2)
        last = sorted(float(r["ms"]) for r in self.S["x7wifi"].seeks if r["cell"] == "x8-seek-h1")
        self.assertSeries(b.get_lines()[3].get_xdata(), last)

    def test_fig14(self):
        fig = self.draw("fig14-x8-downloads")
        self.assertSeries(bar_heights(fig, "HTTP/1.1"),
                          [med(n, f"x8-down-h1-{z}") for n in (S2, S3) for z in ("64M", "1G", "5G")])
        for ax, key in zip(fig.axes, ("s2", "s3")):
            self.assertIn(round(self.S[key].link("from"), 6), [round(y, 6) for y in hline_ys(ax)])

    def test_fig15(self):
        fig = self.draw("fig15-3b-windows")
        self.assertSeries(bar_heights(fig, "engine, 4 in flight"),
                          [med(S3B, f"w-{c}-engine") for c in ("256k-4m", "256k-16m", "1m-4m", "1m-16m")])
        self.assertSeries(bar_heights(fig, "engine, 1 in flight"), [med(S3B, f"w-{c}-par1") for c in ("256k-4m", "1m-16m")])
        self.assertSeries(bar_heights(fig, "single request"), [med(S3B, f"w-{c}-single") for c in ("1m-4m", "1m-16m")])
        self.assertIn(round(med(S3B, "w-engine-h1"), 6), [round(y, 6) for y in hline_ys(fig.axes[0])])

    def test_every_figure_draws_from_the_real_results(self):
        out = tempfile.mkdtemp()
        code, text, _ = run("--results", RESULTS, "--out", out, "--formats", "png")
        self.assertEqual(code, 0)
        self.assertIn(f"{len(charts.FIGURES)} figures in", text)
        self.assertNotIn("skipped", text)


if __name__ == "__main__":
    unittest.main()
