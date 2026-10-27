#!/usr/bin/env python3
"""Draws the thesis figures from the benchmark sessions in bench/results.

    python3 bench/charts.py [--results DIR] [--out DIR] [--formats pdf,png]

Each figure says which sessions it needs; one whose sessions aren't there,
or have none of its cells, is skipped with a note, so the script runs on any
subset. It writes each figure in the formats asked for (PDF and PNG by
default), and an index.md of captions and sources. It reads the results and
never changes them.
"""

import argparse
import csv
import os
import re
import sys
from dataclasses import dataclass, field

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

MiB = 1 << 20
GiB = 1 << 30

# Okabe and Ito's palette, which readers with any common colour-vision
# deficiency can tell apart; hatches and markers tell series apart in
# greyscale print.
COLOURS = ["#0072B2", "#E69F00", "#009E73", "#D55E00", "#CC79A7", "#56B4E9", "#000000", "#F0E442"]
HATCHES = ["", "//", "..", "xx", "\\\\", "oo"]
MARKERS = ["o", "s", "^", "D", "v", "P"]

OK_CODES = {"200", "201", "206"}


@dataclass
class Session:
    """One session's results: the measured runs, without warm-ups, runs
    that failed, and runs set aside by EXCLUDE."""

    key: str
    name: str
    label: str
    rows: list = field(default_factory=list)
    seeks: list = field(default_factory=list)
    env: str = ""
    dropped: int = 0
    excluded: int = 0

    def cell(self, name):
        return [r for r in self.rows if r["scenario"] == name]

    def values(self, name, column, scale=1.0):
        out = []
        for r in self.cell(name):
            v = num(r.get(column))
            if v is not None:
                out.append(v * scale)
        return out

    def seek_times(self, cell, column):
        return [v for v in (num(r.get(column)) for r in self.seeks if r.get("cell") == cell) if v is not None]

    def link(self, direction="to"):
        """The iperf3 TCP rate to or from the server in MiB/s, the mean of
        the session's start and end measurements; None when the session's
        environment file has none."""
        rates = [float(m.group(1 if direction == "to" else 2)) for m in IPERF.finditer(self.env)]
        if not rates:
            return None
        return float(np.mean(rates)) * 1e6 / 8 / MiB


IPERF = re.compile(r"iperf3 at the (?:start|end), Mbit/s: to the server (\d+(?:\.\d+)?), from the server (\d+(?:\.\d+)?)")

# The sessions the figures draw on, by the name their files carry.
SESSIONS = {
    "s1": ("session-1-loopback-20261021-113623", "loopback (session 1)"),
    "s2": ("session-2-lan-20261021-134011", "LAN (session 2)"),
    "s3": ("session-2-lan-20261022-003044", "Wi-Fi (session 3)"),
    "s3b": ("session-3b-windows-20261022-180157", "Wi-Fi (session 3b)"),
    "x13": ("session-13-swap-20261022-152333", "LAN, roles swapped (X13)"),
    "x6lan": ("session-2-lan-20261022-160558", "LAN after M9"),
    "x6loop": ("session-1-loopback-20261026-131827", "loopback after M9"),
    "x7lan": ("session-2-lan-20261023-113117", "LAN (X7/X8)"),
    "x7wifi": ("session-2-lan-20261023-124658", "Wi-Fi (X7/X8)"),
}

# Runs the session reports set apart, by their place in the session's order.
# X6's loopback run after M9: its last 13 runs ran 26-48% slower in every
# cell at once, with no more CPU per GiB, so something outside the benchmark
# slowed them.
EXCLUDE = {
    "session-1-loopback-20261026-131827": lambda seq: seq >= 54,
}


def num(v):
    if v is None or v == "":
        return None
    try:
        return float(v)
    except ValueError:
        return None


def refusals(retried):
    """The 503 answers in a run's retried column, such as "503x2737" or
    "429x3 503x12"."""
    total = 0
    for part in (retried or "").split():
        code, _, n = part.partition("x")
        if code == "503" and n.isdigit():
            total += int(n)
    return total


def load(results, name, key, label):
    base = os.path.join(results, name)
    if not os.path.exists(base + ".csv"):
        return None
    s = Session(key=key, name=name, label=label)
    skip = EXCLUDE.get(name)
    order = {}
    if skip and os.path.exists(base + "-order.csv"):
        with open(base + "-order.csv", newline="") as f:
            for r in csv.DictReader(f):
                try:
                    order[(r["cell"], r["rep"])] = int(r["seq"])
                except (KeyError, TypeError, ValueError):
                    raise ValueError(f"its order file has a bad line: {r}") from None
    with open(base + ".csv", newline="") as f:
        for r in csv.DictReader(f):
            if r.get("rep") == "0":
                continue
            if r.get("http_code") not in OK_CODES:
                s.dropped += 1
                continue
            if skip:
                seq = order.get((r["scenario"], r["rep"]))
                if seq is None:
                    raise ValueError(f"run {r['scenario']} {r['rep']} isn't in its order file, "
                                     "so the runs its report sets apart can't be found")
                if skip(seq):
                    s.excluded += 1
                    continue
            s.rows.append(r)
    if os.path.exists(base + "-seeks.csv"):
        with open(base + "-seeks.csv", newline="") as f:
            for r in csv.DictReader(f):
                if r.get("rep") != "0" and r.get("http_code") in OK_CODES:
                    s.seeks.append(r)
    if os.path.exists(base + "-env.txt"):
        with open(base + "-env.txt", encoding="utf-8", errors="replace") as f:
            s.env = f.read()
    return s


def summary(values):
    """The median and interquartile range, or None for no values."""
    if not values:
        return None
    q1, med, q3 = np.percentile(values, [25, 50, 75])
    return float(med), float(q1), float(q3)


# --- drawing -----------------------------------------------------------------

FIGURES = []


def figure(name, needs, caption):
    def register(fn):
        FIGURES.append((name, needs, caption, fn))
        return fn

    return register


def style():
    plt.rcParams.update({
        "svg.hashsalt": "gocalbox",
        "font.size": 9,
        "axes.titlesize": 9.5,
        "axes.labelsize": 9,
        "legend.fontsize": 8,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linewidth": 0.6,
        "savefig.dpi": 300,
        "pdf.fonttype": 42,
    })


class NoData(Exception):
    """A panel would be drawn empty: its session lacks the cells."""


def bars(ax, groups, series, data, ylabel, first_colour=0):
    """Grouped bars of medians with interquartile whiskers. data maps
    (group, series) to the run values; a missing pair leaves a gap, and a
    panel with no values at all is refused."""
    width = 0.8 / max(1, len(series))
    x = np.arange(len(groups))
    used = []
    for i, s in enumerate(series):
        meds, lo, hi, xs = [], [], [], []
        for j, g in enumerate(groups):
            st = summary(data.get((g, s), []))
            if st is None:
                continue
            m, q1, q3 = st
            xs.append(x[j] + (i - (len(series) - 1) / 2) * width)
            meds.append(m)
            lo.append(m - q1)
            hi.append(q3 - m)
        if not xs:
            continue
        c = (first_colour + i) % len(COLOURS)
        ax.bar(xs, meds, width * 0.92, yerr=[lo, hi], capsize=2, label=s,
               color=COLOURS[c], hatch=HATCHES[c % len(HATCHES)],
               edgecolor="white" if HATCHES[c % len(HATCHES)] == "" else "#333333", linewidth=0.5,
               error_kw={"elinewidth": 0.8})
        used.append(s)
    if not used:
        raise NoData(f"no values for {', '.join(series)}")
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel(ylabel)
    ax.grid(axis="x", visible=False)
    return used


def legend_below(fig, axes, ncol=4):
    """One legend for the figure, under its panels, so it never covers
    data."""
    handles, labels = [], []
    for ax in axes:
        for h, lab in zip(*ax.get_legend_handles_labels()):
            if lab not in labels:
                handles.append(h)
                labels.append(lab)
    if handles:
        fig.tight_layout()
        fig.legend(handles, labels, frameon=False, loc="upper center", ncol=min(ncol, len(labels)),
                   bbox_to_anchor=(0.5, 0.0), fontsize=7.5)


def link_line(ax, rate, text="link (iperf3)"):
    if rate:
        ax.axhline(rate, color="#555555", linestyle="--", linewidth=0.9)
        ax.annotate(f"{text}, {rate:.0f} MiB/s", xy=(1, rate), xycoords=("axes fraction", "data"),
                    xytext=(-2, 3), textcoords="offset points", ha="right", va="bottom", fontsize=7, color="#555555")


def size_label(cell):
    return cell.rsplit("-", 1)[-1].replace("M", " MiB").replace("G", " GiB")


@figure("fig01-x1-uploads", ["s1"],
        "Upload throughput on loopback by path and file size: the resumable engine and the single-request "
        "upload, each over HTTP/2 and HTTP/1.1. 1 MiB files are drawn apart (a), on their own scale. Bars "
        "are medians of 10 runs (5 for 5 GiB); whiskers the interquartile range.")
def fig_x1_uploads(S):
    s = S["s1"]
    paths = [("engine-h2", "engine, HTTP/2"), ("engine-h1", "engine, HTTP/1.1"),
             ("single-h2", "single request, HTTP/2"), ("single-h1", "single request, HTTP/1.1")]
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 3.0), gridspec_kw={"width_ratios": [1, 3]})
    for ax, sizes in ((a, ["1M"]), (b, ["64M", "1G", "5G"])):
        data = {(size_label("x-" + z), label): s.values(f"x1-{key}-{z}", "mib_per_s")
                for z in sizes for key, label in paths}
        bars(ax, [size_label("x-" + z) for z in sizes], [p[1] for p in paths], data, "MiB/s" if ax is a else "")
        ax.set_xlabel("file size")
    a.set_title("(a)", loc="left")
    b.set_title("(b)", loc="left")
    legend_below(fig, [a])
    return fig, [s]


@figure("fig02-x1-downloads-batch", ["s1"],
        "Downloads on loopback by file size and protocol (a), and a batch of 100 files of 1 MiB uploaded "
        "with 1, 4 or 16 at once (b). Medians with interquartile whiskers.")
def fig_x1_downloads(S):
    s = S["s1"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 2.8), gridspec_kw={"width_ratios": [3, 2]})
    sizes = ["64M", "1G", "5G"]
    data = {(size_label("x-" + z), lab): s.values(f"x1-down-{p}-{z}", "mib_per_s")
            for z in sizes for p, lab in [("h2", "HTTP/2"), ("h1", "HTTP/1.1")]}
    bars(a, [size_label("x-" + z) for z in sizes], ["HTTP/2", "HTTP/1.1"], data, "MiB/s")
    a.set_title("(a) downloads", loc="left")
    a.set_xlabel("file size")
    data = {(str(c), "batch"): s.values(f"x1-batch-c{c}", "mib_per_s") for c in (1, 4, 16)}
    bars(b, ["1", "4", "16"], ["batch"], data, "MiB/s", first_colour=2)
    b.set_title("(b) 100 × 1 MiB, HTTP/2", loc="left")
    b.set_xlabel("files at once")
    legend_below(fig, [a])
    return fig, [s]


@figure("fig03-x1-cpu", ["s1"],
        "Server CPU time per GiB uploaded on loopback, by path, for files of 1 and 5 GiB. Medians with "
        "interquartile whiskers.")
def fig_x1_cpu(S):
    s = S["s1"]
    paths = [("engine-h2", "engine, HTTP/2"), ("engine-h1", "engine, HTTP/1.1"),
             ("single-h2", "single, HTTP/2"), ("single-h1", "single, HTTP/1.1")]
    data = {}
    for sz in ("1G", "5G"):
        for key, label in paths:
            vals = []
            for r in s.cell(f"x1-{key}-{sz}"):
                cpu, size, files = num(r["server_cpu_s"]), num(r["size_bytes"]), num(r["files"]) or 1
                if cpu is not None and size:
                    vals.append(cpu / (size * files / GiB))
            data[(size_label("x-" + sz), label)] = vals
    fig, ax = plt.subplots(figsize=(5.0, 2.8))
    bars(ax, ["1 GiB", "5 GiB"], [p[1] for p in paths], data, "server CPU s per GiB")
    ax.set_xlabel("file size")
    legend_below(fig, [ax])
    return fig, [s]


@figure("fig04-x2-guarantees", ["s1"],
        "What the guarantees cost on loopback. (a) The engine in process with the default audit, every "
        "part audited, and without waiting for the audit log, for 200 files of 1 MiB and one of 1 GiB. "
        "(b) The single-request upload and a batch of 100 files before M6's staging and after it.")
def fig_x2(S):
    s = S["s1"]
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 2.8))
    modes = [("default", "default"), ("parts", "every part audited"), ("nowait", "no audit wait")]
    data = {(sz, lab): s.values(f"x2-audit-{m}-{z}", "mib_per_s")
            for z, sz in [("1M", "200 × 1 MiB"), ("1G", "1 GiB")] for m, lab in modes}
    bars(a, ["200 × 1 MiB", "1 GiB"], [m[1] for m in modes], data, "MiB/s")
    a.set_title("(a) audit", loc="left")
    groups = [("64 MiB", "x2-staged-{}-64M"), ("1 GiB", "x2-staged-{}-1G"), ("batch, 4 at once", "x2-batch-{}-c4")]
    data = {(g, lab): s.values(cell.format(v), "mib_per_s") for g, cell in groups
            for v, lab in [("pre", "before M6"), ("now", "after M6")]}
    bars(b, [g[0] for g in groups], ["before M6", "after M6"], data, "MiB/s", first_colour=3)
    b.set_title("(b) staging, HTTP/2", loc="left")
    legend_below(fig, [a, b], ncol=5)
    return fig, [s]


@figure("fig05-x3-complete", ["s1"],
        "Time to complete an upload against its size, in process on the NVMe disk. Each point is a run; "
        "the line joins the medians. Completing doesn't read the file again, so its time stays flat.")
def fig_x3(S):
    s = S["s1"]
    sizes = [("1M", MiB), ("64M", 64 * MiB), ("1G", GiB), ("5G", 5 * GiB), ("20G", 20 * GiB), ("50G", 50 * GiB)]
    fig, ax = plt.subplots(figsize=(5.0, 2.8))
    xs, meds = [], []
    for z, b in sizes:
        v = s.values(f"x3-nvme-{z}", "complete_p50_ms")
        if not v:
            continue
        ax.scatter([b / MiB] * len(v), v, s=12, color=COLOURS[0], alpha=0.6, linewidths=0)
        xs.append(b / MiB)
        meds.append(float(np.median(v)))
    if not xs:
        raise NoData("no x3 cells")
    ax.plot(xs, meds, color=COLOURS[0], linewidth=1)
    ax.set_xscale("log")
    ax.set_xticks([b / MiB for _, b in sizes])
    ax.set_xticklabels([size_label("x-" + z) for z, _ in sizes], rotation=30, ha="right")
    ax.minorticks_off()
    ax.set_ylim(bottom=0)
    ax.set_xlabel("file size (log scale)")
    ax.set_ylabel("complete, ms")
    return fig, [s]


@figure("fig06-x4-parallel", ["s2", "s3"],
        "Upload throughput of a 1 GiB file against the parts in flight, for part sizes of 8, 16 and 64 MiB, "
        "over the LAN and over Wi-Fi. Lines join medians; bands span the interquartile range.")
def fig_x4(S):
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.8), sharey=True)
    used = []
    for ax, key, title in zip(axes, ["s2", "s3"], ["(a) LAN", "(b) Wi-Fi"]):
        s = S[key]
        used.append(s)
        for i, p in enumerate([8, 16, 64]):
            xs, m, lo, hi = [], [], [], []
            for par in (1, 2, 4, 8):
                st = summary(s.values(f"x4-p{p}-par{par}-1G", "mib_per_s"))
                if st:
                    xs.append(par)
                    m.append(st[0])
                    lo.append(st[1])
                    hi.append(st[2])
            if not xs:
                raise NoData(f"{s.name} has no x4 cells for {p} MiB parts")
            ax.plot(xs, m, marker=MARKERS[i], color=COLOURS[i], label=f"{p} MiB parts", markersize=4, linewidth=1)
            ax.fill_between(xs, lo, hi, color=COLOURS[i], alpha=0.15, linewidth=0)
        link_line(ax, s.link("to"))
        ax.set_xscale("log", base=2)
        ax.set_xticks([1, 2, 4, 8])
        ax.set_xticklabels(["1", "2", "4", "8"])
        ax.minorticks_off()
        ax.set_title(title, loc="left")
        ax.set_xlabel("parts in flight")
        ax.set_ylim(bottom=0)
    axes[0].set_ylabel("MiB/s")
    legend_below(fig, axes)
    return fig, used


@figure("fig07-x5-protocol", ["s2", "s3"],
        "HTTP/2 against HTTP/1.1 for 1 GiB, over the LAN and over Wi-Fi: the engine and the single-request "
        "upload, and downloads. Medians with interquartile whiskers. The dashed lines are the link's TCP "
        "rate measured by iperf3, to the server over the uploads and from it over the downloads.")
def fig_x5_protocol(S):
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.8), sharey=True)
    used = []
    groups = [("engine", "engine"), ("single", "single request"), ("down", "download")]
    for ax, key, title in zip(axes, ["s2", "s3"], ["(a) LAN", "(b) Wi-Fi"]):
        s = S[key]
        used.append(s)
        data = {(lab, pl): s.values(f"x5-{g}-{p}", "mib_per_s")
                for g, lab in groups for p, pl in [("h2", "HTTP/2"), ("h1", "HTTP/1.1")]}
        bars(ax, [g[1] for g in groups], ["HTTP/2", "HTTP/1.1"], data, "MiB/s" if key == "s2" else "")
        for rate, x0, x1 in ((s.link("to"), -0.5, 1.5), (s.link("from"), 1.5, 2.5)):
            if rate:
                ax.hlines(rate, x0, x1, color="#555555", linestyle="--", linewidth=0.9)
        ax.set_xlim(-0.5, 2.5)
        ax.set_title(title, loc="left")
    legend_below(fig, axes)
    return fig, used


@figure("fig08-x5-windows", ["s1", "s2", "s3"],
        "The server's HTTP/2 stream window, for a 1 GiB upload through the engine (4 parts in flight) and "
        "the single-request upload, on loopback, the LAN and Wi-Fi. 256 KiB is the default; 1 MiB comes "
        "with a 16 MiB connection window, the others with 4 MiB.")
def fig_x5_windows(S):
    fig, axes = plt.subplots(1, 3, figsize=(6.3, 2.6))
    used = []
    windows = [("w128", "128K"), ("w256", "256K"), ("w448", "448K"), ("w1m", "1M")]
    for ax, key, title in zip(axes, ["s1", "s2", "s3"], ["(a) loopback", "(b) LAN", "(c) Wi-Fi"]):
        s = S[key]
        used.append(s)
        data = {(wl, lab): s.values(f"x5-{w}-{p}", "mib_per_s")
                for w, wl in windows for p, lab in [("engine", "engine"), ("single", "single request")]}
        bars(ax, [w[1] for w in windows], ["engine", "single request"], data, "MiB/s" if key == "s1" else "")
        if key != "s1":
            link_line(ax, s.link("to"), "link")
        ax.set_title(title, loc="left")
        ax.set_xlabel("stream window")
    legend_below(fig, axes)
    return fig, used


@figure("fig09-x13-swap", ["s2", "x13"],
        "The roles swapped (X13): server on PC B and client on PC A, against session 2's usual roles, for "
        "1 GiB over the LAN. Medians with interquartile whiskers.")
def fig_x13(S):
    s2, x = S["s2"], S["x13"]
    cells = [("engine-h2", "engine\nHTTP/2"), ("engine-h1", "engine\nHTTP/1.1"), ("single-h2", "single\nHTTP/2"),
             ("single-h1", "single\nHTTP/1.1"), ("down-h2", "download\nHTTP/2"), ("down-h1", "download\nHTTP/1.1")]
    data = {}
    for c, lab in cells:
        data[(lab, "server PC A (session 2)")] = s2.values(f"x5-{c}", "mib_per_s")
        data[(lab, "server PC B (X13)")] = x.values(f"x13-{c}", "mib_per_s")
    fig, ax = plt.subplots(figsize=(6.3, 2.8))
    bars(ax, [c[1] for c in cells], ["server PC A (session 2)", "server PC B (X13)"], data, "MiB/s")
    link_line(ax, s2.link("to"))
    legend_below(fig, [ax])
    return fig, [s2, x]


USERS = [1, 2, 4, 8, 16, 24]


def by_users(s, value):
    """value(rows) for each user count, None where the session has no such
    cell, so that lines break across user counts it didn't measure."""
    out = []
    for u in USERS:
        rows = s.cell(f"x6-users-{u}")
        out.append(value(rows) if rows else None)
    return out


def users_axis(ax):
    ax.set_xscale("log", base=2)
    ax.set_xticks(USERS)
    ax.set_xticklabels([str(u) for u in USERS])
    ax.minorticks_off()
    ax.set_xlabel("users")


def measured(values, i=None):
    """The user counts measured, and the values there: lines join measured
    counts, as the caption says which weren't."""
    xs = [u for u, v in zip(USERS, values) if v is not None]
    ys = [v if i is None else v[i] for v in values if v is not None]
    return xs, ys


@figure("fig10-x6-throughput", ["s1", "s2", "x6loop", "x6lan"],
        "Total upload throughput against the number of users, each with its own login and connection and "
        "3 files of 256 MiB, before M9 (parts refused when every slot is taken) and after it (parts wait "
        "for a slot), on loopback and over the LAN. Lines join the medians at the counts measured; bands "
        "span the interquartile range. Over the LAN, 2 and 8 users weren't measured.")
def fig_x6_throughput(S):
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.8))
    used = []
    for ax, (before, after), title in zip(axes, [("s1", "x6loop"), ("s2", "x6lan")], ["(a) loopback", "(b) LAN"]):
        for i, (key, lab) in enumerate([(before, "before M9"), (after, "after M9")]):
            s = S[key]
            used.append(s)
            st = by_users(s, lambda rows: summary([v for v in (num(r["mib_per_s"]) for r in rows) if v is not None]))
            if not any(st):
                raise NoData(f"{s.name} has no x6 cells")
            ax.plot(*measured(st, 0), marker=MARKERS[i], color=COLOURS[i], label=lab, markersize=4, linewidth=1)
            xs, lo = measured(st, 1)
            ax.fill_between(xs, lo, measured(st, 2)[1], color=COLOURS[i], alpha=0.15, linewidth=0)
        if before == "s2":
            link_line(ax, S["s2"].link("to"))
        users_axis(ax)
        ax.set_ylim(bottom=0)
        ax.set_title(title, loc="left")
    axes[0].set_ylabel("total MiB/s")
    legend_below(fig, axes)
    return fig, used


@figure("fig11-x6-fairness", ["s1", "s2", "x6loop", "x6lan"],
        "Fairness and refusals against the number of users, before and after M9, on loopback and over the "
        "LAN: (a) the slowest user's rate over the fastest's, medians with interquartile whiskers; (b) the "
        "503 answers per run, medians, on a symmetric log scale. Over the LAN, 2 and 8 users weren't measured.")
def fig_x6_fairness(S):
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 2.8))
    used = []
    series = [("s1", "loopback, before M9"), ("x6loop", "loopback, after M9"), ("s2", "LAN, before M9"), ("x6lan", "LAN, after M9")]
    top = 0
    for i, (key, lab) in enumerate(series):
        s = S[key]
        used.append(s)

        def ratio(rows):
            vals = []
            for r in rows:
                lo, hi = num(r["user_min_mib_s"]), num(r["user_max_mib_s"])
                if lo is not None and hi:
                    vals.append(lo / hi)
            return summary(vals)

        ratios = by_users(s, ratio)
        refused = by_users(s, lambda rows: float(np.median([refusals(r["retried"]) for r in rows])))
        if not any(ratios):
            raise NoData(f"{s.name} has no x6 fairness")
        top = max([top] + [v for v in refused if v is not None])
        dash = "-" if "after" in lab else ":"
        xs, med = measured(ratios, 0)
        got = [r for r in ratios if r is not None]
        err = [[r[0] - r[1] for r in got], [r[2] - r[0] for r in got]]
        a.errorbar(xs, med, yerr=err, marker=MARKERS[i], color=COLOURS[i], linestyle=dash, label=lab,
                   markersize=4, linewidth=1, capsize=2)
        # On a log scale a line between measured counts would read as a
        # measured rise, so refusals are joined only between neighbours.
        b.plot(USERS, [np.nan if v is None else v for v in refused], marker=MARKERS[i], color=COLOURS[i],
               linestyle=dash, label=lab, markersize=4, linewidth=1)
    for ax in (a, b):
        users_axis(ax)
    a.set_ylim(0, 1.05)
    a.set_ylabel("slowest / fastest user")
    a.set_title("(a) fairness", loc="left")
    b.set_yscale("symlog", linthresh=10)
    b.set_ylim(0, max(100, top * 2))
    b.set_ylabel("503 answers per run")
    b.set_title("(b) refusals", loc="left")
    legend_below(fig, [a], ncol=2)
    return fig, used


X7_FAULTS = [("stop", "client stops and resumes"), ("kill", "server killed and restarted"), ("cut", "network cut for 10 s")]

# The rate each session's report counts the rest of the file at: over the
# cable, the link's; over Wi-Fi, where the engine doesn't fill the link, the
# uploads' own median rate before their fault, which the CSV doesn't hold.
X7_REFERENCE = {
    "x7lan": (111.6, "rest of the file at the link's rate, 111.6 MiB/s"),
    "x7wifi": (99.4, "rest of the file at the uploads' own rate before the fault, 99.4 MiB/s"),
}


@figure("fig12-x7-resume", ["x7lan", "x7wifi", "s3"],
        "Resuming a 5 GiB upload over HTTP/2: the time from the fault to the file's end, against the share "
        "of the file's parts in when the fault came, over the LAN and over Wi-Fi. Each point is a run "
        "(5 per share). The dashed lines are the rest of the file at the rate the session reports count "
        "against: the link's over the LAN, and over Wi-Fi the uploads' own rate before the fault, since "
        "the engine doesn't fill the link there. The 60 s cut at 50% is drawn apart. Over Wi-Fi the "
        "client's stops come from session 3, another day.")
def fig_x7(S):
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 3.0), sharey=True)
    used = []
    size = 5 * GiB / MiB
    for ax, key, title in zip(axes, ["x7lan", "x7wifi"], ["(a) LAN", "(b) Wi-Fi"]):
        s = S[key]
        used.append(s)
        drawn = 0
        for i, (fault, lab) in enumerate(X7_FAULTS):
            src = S["s3"] if fault == "stop" and key == "x7wifi" else s
            for share in (10, 50, 90):
                v = src.values(f"x7-{fault}-{share}", "resume_p50_s")
                if not v:
                    continue
                drawn += len(v)
                jitter = (i - 1) * 2.2
                ax.scatter([share + jitter] * len(v), v, s=14, color=COLOURS[i], marker=MARKERS[i],
                           label=lab, alpha=0.8, linewidths=0)
        if not drawn:
            raise NoData(f"{s.name} has no x7 cells")
        v = s.values("x7-cut-50-60s", "resume_p50_s")
        if v:
            ax.scatter([50 + 4.4] * len(v), v, s=14, color=COLOURS[3], marker=MARKERS[3], label="network cut for 60 s",
                       alpha=0.8, linewidths=0)
        rate, lab = X7_REFERENCE[key]
        xs = np.linspace(5, 95, 50)
        ax.plot(xs, size * (1 - xs / 100) / rate, color=COLOURS[6] if key == "x7wifi" else "#555555",
                linestyle="--", linewidth=0.9, label=lab)
        ax.set_xticks([10, 50, 90])
        ax.set_xticklabels(["10%", "50%", "90%"])
        ax.set_xlabel("share of the parts in at the fault")
        ax.set_title(title, loc="left")
        ax.margins(y=0.08)
        ax.set_ylim(bottom=0)
    used.append(S["s3"])
    axes[0].set_ylabel("fault to end, s")
    legend_below(fig, axes, ncol=2)
    return fig, used


def ecdf(ax, values, **kw):
    v = np.sort(values)
    if len(v) == 0:
        raise NoData("no seeks")
    ax.step(v, np.arange(1, len(v) + 1) / len(v), where="post", **kw)


@figure("fig13-x8-seeks", ["x7lan", "x7wifi"],
        "Seeks: 100 Range requests of 1 MiB at random offsets in a 1 GiB file, one after another on one "
        "connection, after the server's page cache was dropped; 1,000 seeks per line. (a) Time to the first "
        "byte, (b) time to the last byte, as cumulative shares, on log scales.")
def fig_x8_seeks(S):
    fig, (a, b) = plt.subplots(1, 2, figsize=(6.3, 2.8), sharey=True)
    used = []
    for colour, (key, where) in zip((COLOURS[0], COLOURS[3]), [("x7lan", "LAN"), ("x7wifi", "Wi-Fi")]):
        s = S[key]
        used.append(s)
        for cell, proto in [("x8-seek-h2", "HTTP/2"), ("x8-seek-h1", "HTTP/1.1")]:
            dash = "-" if proto == "HTTP/2" else "--"
            ecdf(a, s.seek_times(cell, "first_byte_ms"), color=colour, linestyle=dash, label=f"{where}, {proto}", linewidth=1)
            ecdf(b, s.seek_times(cell, "ms"), color=colour, linestyle=dash, linewidth=1)
    for ax, title in [(a, "(a) to the first byte"), (b, "(b) to the last byte")]:
        ax.set_xscale("log")
        ax.set_xlabel("ms (log scale)")
        ax.set_title(title, loc="left")
    a.set_ylabel("share of seeks")
    legend_below(fig, [a])
    return fig, used


@figure("fig14-x8-downloads", ["s2", "s3"],
        "Download throughput by file size and protocol over the LAN and over Wi-Fi, from disk after the "
        "server's page cache was dropped. Medians with interquartile whiskers; the dashed line is the link's "
        "TCP rate from the server, measured by iperf3.")
def fig_x8_downloads(S):
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.8), sharey=True)
    used = []
    sizes = ["64M", "1G", "5G"]
    for ax, key, title in zip(axes, ["s2", "s3"], ["(a) LAN", "(b) Wi-Fi"]):
        s = S[key]
        used.append(s)
        data = {(size_label("x-" + z), pl): s.values(f"x8-down-{p}-{z}", "mib_per_s")
                for z in sizes for p, pl in [("h2", "HTTP/2"), ("h1", "HTTP/1.1")]}
        bars(ax, [size_label("x-" + z) for z in sizes], ["HTTP/2", "HTTP/1.1"], data, "MiB/s" if key == "s2" else "")
        link_line(ax, s.link("from"))
        ax.set_title(title, loc="left")
        ax.set_xlabel("file size")
    legend_below(fig, axes)
    return fig, used


@figure("fig15-3b-windows", ["s3b"],
        "HTTP/2's two windows over Wi-Fi (session 3b), one changed at a time, for 1 GiB: the engine with "
        "4 parts in flight and with 1, and the single-request upload, against the engine over HTTP/1.1 "
        "(dotted). Medians with interquartile whiskers. Session 3b measured one part in flight at "
        "256K / 4M and 1M / 16M only, and the single request at 1M only; session 3 has the single request "
        "at 256K / 4M, 10.0 MiB/s (fig07).")
def fig_3b(S):
    s = S["s3b"]
    combos = [("256k-4m", "256K / 4M"), ("256k-16m", "256K / 16M"), ("1m-4m", "1M / 4M"), ("1m-16m", "1M / 16M")]
    data = {}
    for c, lab in combos:
        data[(lab, "engine, 4 in flight")] = s.values(f"w-{c}-engine", "mib_per_s")
        data[(lab, "engine, 1 in flight")] = s.values(f"w-{c}-par1", "mib_per_s")
        data[(lab, "single request")] = s.values(f"w-{c}-single", "mib_per_s")
    fig, ax = plt.subplots(figsize=(6.3, 2.8))
    bars(ax, [c[1] for c in combos], ["engine, 4 in flight", "engine, 1 in flight", "single request"], data, "MiB/s")
    h1 = summary(s.values("w-engine-h1", "mib_per_s"))
    if h1:
        ax.axhline(h1[0], color=COLOURS[6], linestyle=":", linewidth=1, label=f"engine over HTTP/1.1, {h1[0]:.0f} MiB/s")
    ax.set_xlabel("stream window / connection window")
    legend_below(fig, [ax])
    return fig, [s]


# --- running -----------------------------------------------------------------


def save(fig, out, name, formats):
    paths = []
    for fmt in formats:
        p = os.path.join(out, f"{name}.{fmt}")
        # No dates in the files, so the same results draw the same bytes.
        meta = {"pdf": {"CreationDate": None}, "svg": {"Date": None}}.get(fmt, {})
        fig.savefig(p, bbox_inches="tight", metadata=meta)
        paths.append(p)
    plt.close(fig)
    return paths


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", default=os.path.join(here, "results"))
    ap.add_argument("--out", default=os.path.join(here, "charts"))
    ap.add_argument("--formats", default="pdf,png")
    ap.add_argument("--only", default="", help="comma-separated figure names to draw")
    args = ap.parse_args(argv)

    formats = [f for f in args.formats.split(",") if f]
    for f in formats:
        if f not in ("pdf", "png", "svg"):
            ap.error(f"unknown format {f!r}: pdf, png or svg")
    only = {n for n in args.only.split(",") if n}
    known = {f[0] for f in FIGURES}
    if only - known:
        ap.error(f"unknown figures: {', '.join(sorted(only - known))}")
    if not os.path.isdir(args.results):
        ap.error(f"no results folder {args.results}")

    sessions = {}
    unused = set()
    for key, (name, label) in SESSIONS.items():
        try:
            s = load(args.results, name, key, label)
        except ValueError as e:
            print(f"{name}: not used: {e}")
            unused.add(key)
            continue
        if s is not None:
            sessions[key] = s
            notes = []
            if s.dropped:
                notes.append(f"{s.dropped} failed runs left out")
            if s.excluded:
                notes.append(f"{s.excluded} runs set apart")
            print(f"{name}: {len(s.rows)} runs" + (f" ({'; '.join(notes)})" if notes else ""))

    os.makedirs(args.out, exist_ok=True)
    style()
    index = ["# Figures", "", f"Drawn by `bench/charts.py` from `bench/results`, as {', '.join(f.upper() for f in formats)}.", ""]
    drawn = skipped = 0
    kept = set()
    not_drawn = []
    for name, needs, caption, fn in FIGURES:
        if only and name not in only:
            continue
        missing = [SESSIONS[k][0] for k in needs if k not in sessions]
        if missing:
            parts = []
            for why, keys in (("not used", [k for k in needs if k in unused]),
                              ("missing", [k for k in needs if k not in sessions and k not in unused])):
                if keys:
                    parts.append(f"{why}: {', '.join(SESSIONS[k][0] for k in keys)}")
            print(f"{name}: skipped, {'; '.join(parts)}")
            not_drawn.append(name)
            skipped += 1
            continue
        try:
            fig, used = fn(sessions)
        except NoData as e:
            plt.close("all")
            print(f"{name}: skipped, {e}")
            not_drawn.append(name)
            skipped += 1
            continue
        save(fig, args.out, name, formats)
        kept.update(f"{name}.{f}" for f in formats)
        drawn += 1
        srcs = ", ".join(f"`{n}`" for n in dict.fromkeys(s.name for s in used))
        index += [f"## {name}", "", caption, "", f"Sources: {srcs}.", ""]
    if only:
        print("index.md left as it was, since only some figures were drawn")
    else:
        # A figure drawn now loses the formats it no longer has. One not drawn
        # keeps its files, which may be committed, and the index says so.
        for name in (n for n, *_ in FIGURES if n not in not_drawn):
            for fmt in ("pdf", "png", "svg"):
                stale = f"{name}.{fmt}"
                if stale not in kept and os.path.exists(os.path.join(args.out, stale)):
                    os.remove(os.path.join(args.out, stale))
        for name, needs, caption, _ in FIGURES:
            if name in not_drawn and any(os.path.exists(os.path.join(args.out, f"{name}.{f}")) for f in ("pdf", "png", "svg")):
                srcs = ", ".join(f"`{SESSIONS[k][0]}`" for k in needs)
                index += [f"## {name} (from an earlier run)", "", caption, "",
                          f"Sources: {srcs}. Not drawn this time; its files are an earlier run's.", ""]
        with open(os.path.join(args.out, "index.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(index))
    print(f"{drawn} figures in {args.out}" + (f", {skipped} skipped" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
