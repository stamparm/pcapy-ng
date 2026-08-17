# pcapy-ng benchmarks

Measurement harness for the classic and the 2.0 capture APIs. It is deliberately separate
from `tests/` — nothing here runs as part of the test suite, and nothing here is imported by
the package.

The point of this harness is to find out **where each API helps and where it does not**. Any
scenario where a newer API is not faster is reported as such; see "Reading the results".

```sh
python3 gen_pcap.py                 # once: build the deterministic capture (~175 MiB)
python3 bench.py --reps 5           # run everything -> results/
python3 bench.py --only 'flowheads' # run a subset
```

`gen_pcap.py` and `bench.py` need a Python with `pcapy-ng` importable; `bench.py` re-executes
itself with `sys.executable`, so run it with the interpreter you want to measure.

## Files

| file | purpose |
|---|---|
| `gen_pcap.py` | deterministic capture generator + JSON manifest (ground truth) |
| `pyequiv.py` | Python implementations of the same decisions the C classifier makes |
| `bench.py` | the harness: scenarios, repetitions, metrics, CSV/JSON/Markdown output |
| `fanout_live.py` | **optional**, Linux-only, live `PACKET_FANOUT` check (not reproducible) |
| `data/` | generated capture + manifest (git-ignored: ~175 MiB, regenerate with `gen_pcap.py`) |
| `results/` | `results.csv`, `results.json`, `SUMMARY.md` — **committed**, so every published number can be checked against the run that produced it |

## Methodology

**Deterministic input.** `gen_pcap.py` is seeded, so the same arguments always produce the
same capture. The default is 400 000 packets (~175 MiB, ~443 B average) of mixed TCP/UDP/ICMP
traffic across ~6 500 flows (~23 600 directional 5-tuple keys), including ~3 % IPv6 and ~2 %
VLAN-tagged frames so both the C classifier and the Python equivalents have to handle the
non-IPv4 and tagged cases.

**Ground truth.** The generator also writes a manifest containing, computed while the packets
are being written: the exact number of packets each address set matches, and the exact number
of flow heads for each cutoff. Every scenario asserts its admitted count against the manifest,
so a "fast" result that silently admitted the wrong packets cannot pass unnoticed.

**No disk in the measurement.** The capture is read once end to end before the first
measurement to warm the page cache, and every repetition then re-reads the same file. The
machine must have enough free RAM to keep the capture cached — check the `peak RSS` column and
the reported free memory if numbers look unstable.

**Process isolation.** Each measurement runs in a fresh subprocess (`bench.py --run-one`), so
peak RSS, the C flow table and any large Python set are attributed to the scenario that
allocated them and cannot leak into the next one.

**What is timed.** Only the capture loop. Opening the reader, packing the address set, building
the Python `set` and allocating the output buffer are setup and are reported separately as
`setup_median_s` — relevant for the 1 000 000-address scenarios, where building the Python set
is a real cost that the C path does not pay in the same form.

**Repetitions.** `--reps N` (default 5) full rounds, scenario by scenario, so slow drift
affects all scenarios similarly. The report gives median, min, max, stdev and the relative
spread; treat differences smaller than the spread as noise.

**Metrics.** Wall clock (`time.perf_counter`), process CPU time (`time.process_time`), packets
processed per second, packets *delivered to Python* per second, admitted/dropped counts,
overflow (for `loop_to_buffer`) and peak RSS (`ru_maxrss` of the child).

"Delivered to Python" means per-packet Python objects were created: it is the whole capture
for `next()`/`loop()`, the admitted subset for `loop_filtered()`, and zero for
`loop_to_buffer()` and for the metadata-only `next_batch()` variants.

## Fairness rules

1. **Equal-work pairs.** Every `cls_*` / `buf_*` scenario has a `py_*` counterpart that reaches
   the same admitted set in Python on top of the classic API — parsing Ethernet/VLAN/IPv4,
   checking set membership or maintaining a flow dict. The harness prints both admitted counts
   and flags any difference. A speedup is only reported next to the counts that produced it.
2. **Raw overhead is labelled as such.** `next()`, `loop()` and `next_batch()` do different
   amounts of work per packet. They are in their own table, explicitly *not* an equal-work
   comparison; `next_batch` appears twice (metadata-only, and with a per-packet slice so it
   materialises the same objects `next()` does).
3. **The Python side is not sandbagged.** `pyequiv.py` uses precomputed `struct.Struct`
   objects, bound-method lookups hoisted out of the loop, integer sets and a plain dict. It is
   what a competent Python author would write, not a strawman — and not micro-tuned into
   unreadability either.
4. **Set size and key distribution are separated.** The address-set sweep runs twice: once
   padded with consecutive addresses (what expanding CIDR blocks gives you) and once with
   uniformly random ones. The C set is an open-addressing table whose probe behaviour depends
   on key distribution, so collapsing the two would attribute a hashing effect to set size.

## Known semantic difference (reported, not hidden)

The C flow table is a fixed ~12 MB direct-mapped hash (1M slots) that **evicts on collision**;
the Python equivalent uses an exact dict. When two live flows hash to the same slot they evict
each other and their counters restart, so the C path reports a few percent *more* flow heads
than exact per-tuple accounting. That is the documented memory/accuracy trade, so the
flow-head scenarios assert "at least the exact count" and the report prints the actual delta.
Every other scenario matches the manifest exactly.

## PACKET_FANOUT

`set_fanout()` is a live, Linux-only kernel scaling feature: it cannot be measured from an
offline capture, and its results depend on hardware, driver, IRQ affinity and whatever traffic
happens to be on the wire. It is therefore **not** part of the reproducible benchmark. Use
`fanout_live.py` separately, and treat its output as an observation about one machine at one
moment, not as a portable number.

## Reading the results

`results/SUMMARY.md` has four sections: raw API overhead, classification (equal work),
`loop_to_buffer` (equal work), and a paired-speedup table. Things worth checking before
quoting any number:

* the `spread` column — if it is large, the machine was busy;
* the admitted counts — a fast path that admits the wrong number of packets is a bug, not a win;
* `setup_median_s` for the large address sets;
* peak RSS for the buffer scenarios, which allocate the whole capture plus per-record headers.

The committed `results/` is one machine at one moment — the exact CPU, kernel, Python and libpcap
are in the Environment table at the top of `SUMMARY.md`, and every ratio quoted elsewhere in the
project comes from that run. Re-running `bench.py` overwrites all three files.
