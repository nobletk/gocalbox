# Figures

Drawn by `bench/charts.py` from `bench/results`, as PDF, PNG.

## fig01-x1-uploads

Upload throughput on loopback by path and file size: the resumable engine and the single-request upload, each over HTTP/2 and HTTP/1.1. 1 MiB files are drawn apart (a), on their own scale. Bars are medians of 10 runs (5 for 5 GiB); whiskers the interquartile range.

Sources: `session-1-loopback-20261021-113623`.

## fig02-x1-downloads-batch

Downloads on loopback by file size and protocol (a), and a batch of 100 files of 1 MiB uploaded with 1, 4 or 16 at once (b). Medians with interquartile whiskers.

Sources: `session-1-loopback-20261021-113623`.

## fig03-x1-cpu

Server CPU time per GiB uploaded on loopback, by path, for files of 1 and 5 GiB. Medians with interquartile whiskers.

Sources: `session-1-loopback-20261021-113623`.

## fig04-x2-guarantees

What the guarantees cost on loopback. (a) The engine in process with the default audit, every part audited, and without waiting for the audit log, for 200 files of 1 MiB and one of 1 GiB. (b) The single-request upload and a batch of 100 files before M6's staging and after it.

Sources: `session-1-loopback-20261021-113623`.

## fig05-x3-complete

Time to complete an upload against its size, in process on the NVMe disk. Each point is a run; the line joins the medians. Completing doesn't read the file again, so its time stays flat.

Sources: `session-1-loopback-20261021-113623`.

## fig06-x4-parallel

Upload throughput of a 1 GiB file against the parts in flight, for part sizes of 8, 16 and 64 MiB, over the LAN and over Wi-Fi. Lines join medians; bands span the interquartile range.

Sources: `session-2-lan-20261021-134011`, `session-2-lan-20261022-003044`.

## fig07-x5-protocol

HTTP/2 against HTTP/1.1 for 1 GiB, over the LAN and over Wi-Fi: the engine and the single-request upload, and downloads. Medians with interquartile whiskers. The dashed lines are the link's TCP rate measured by iperf3, to the server over the uploads and from it over the downloads.

Sources: `session-2-lan-20261021-134011`, `session-2-lan-20261022-003044`.

## fig08-x5-windows

The server's HTTP/2 stream window, for a 1 GiB upload through the engine (4 parts in flight) and the single-request upload, on loopback, the LAN and Wi-Fi. 256 KiB is the default; 1 MiB comes with a 16 MiB connection window, the others with 4 MiB.

Sources: `session-1-loopback-20261021-113623`, `session-2-lan-20261021-134011`, `session-2-lan-20261022-003044`.

## fig09-x13-swap

The roles swapped (X13): server on PC B and client on PC A, against session 2's usual roles, for 1 GiB over the LAN. Medians with interquartile whiskers.

Sources: `session-2-lan-20261021-134011`, `session-13-swap-20261022-152333`.

## fig10-x6-throughput

Total upload throughput against the number of users, each with its own login and connection and 3 files of 256 MiB, before M9 (parts refused when every slot is taken) and after it (parts wait for a slot), on loopback and over the LAN. Lines join the medians at the counts measured; bands span the interquartile range. Over the LAN, 2 and 8 users weren't measured.

Sources: `session-1-loopback-20261021-113623`, `session-1-loopback-20261026-131827`, `session-2-lan-20261021-134011`, `session-2-lan-20261022-160558`.

## fig11-x6-fairness

Fairness and refusals against the number of users, before and after M9, on loopback and over the LAN: (a) the slowest user's rate over the fastest's, medians with interquartile whiskers; (b) the 503 answers per run, medians, on a symmetric log scale. Over the LAN, 2 and 8 users weren't measured.

Sources: `session-1-loopback-20261021-113623`, `session-1-loopback-20261026-131827`, `session-2-lan-20261021-134011`, `session-2-lan-20261022-160558`.

## fig12-x7-resume

Resuming a 5 GiB upload over HTTP/2: the time from the fault to the file's end, against the share of the file's parts in when the fault came, over the LAN and over Wi-Fi. Each point is a run (5 per share). The dashed lines are the rest of the file at the rate the session reports count against: the link's over the LAN, and over Wi-Fi the uploads' own rate before the fault, since the engine doesn't fill the link there. The 60 s cut at 50% is drawn apart. Over Wi-Fi the client's stops come from session 3, another day.

Sources: `session-2-lan-20261023-113117`, `session-2-lan-20261023-124658`, `session-2-lan-20261022-003044`.

## fig13-x8-seeks

Seeks: 100 Range requests of 1 MiB at random offsets in a 1 GiB file, one after another on one connection, after the server's page cache was dropped; 1,000 seeks per line. (a) Time to the first byte, (b) time to the last byte, as cumulative shares, on log scales.

Sources: `session-2-lan-20261023-113117`, `session-2-lan-20261023-124658`.

## fig14-x8-downloads

Download throughput by file size and protocol over the LAN and over Wi-Fi, from disk after the server's page cache was dropped. Medians with interquartile whiskers; the dashed line is the link's TCP rate from the server, measured by iperf3.

Sources: `session-2-lan-20261021-134011`, `session-2-lan-20261022-003044`.

## fig15-3b-windows

HTTP/2's two windows over Wi-Fi (session 3b), one changed at a time, for 1 GiB: the engine with 4 parts in flight and with 1, and the single-request upload, against the engine over HTTP/1.1 (dotted). Medians with interquartile whiskers. Session 3b measured one part in flight at 256K / 4M and 1M / 16M only, and the single request at 1M only; session 3 has the single request at 256K / 4M, 10.0 MiB/s (fig07).

Sources: `session-3b-windows-20261022-180157`.
