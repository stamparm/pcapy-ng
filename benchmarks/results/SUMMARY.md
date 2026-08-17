# pcapy-ng benchmark results

Offline capture, deterministic input, 5 repetitions per scenario, medians reported.

## Environment

| item | value |
|---|---|
| CPU | AMD Ryzen 7 PRO 4750U with Radeon Graphics (16 logical CPUs) |
| CPU freq policy | {'scaling_governor': 'schedutil', 'scaling_driver': 'acpi-cpufreq', 'scaling_max_freq_khz': 1700000} |
| OS / kernel | Linux-6.8.0-137-generic-x86_64-with-glibc2.39 |
| Python | 3.12.3 (CPython) |
| libpcap | libpcap version 1.10.4 (with TPACKET_V3) |
| libpcap path | `/usr/lib/x86_64-linux-gnu/libpcap.so.1.10.4` |
| pcapy-ng | 2.0.2 (git 639a6a7-dirty) |
| pcapy module | `/tmp/claude-1000/-home-stamparm-Private-Work-pcapy-ng/d862c1ef-6d01-498b-a4a8-be1665f1e781/scratchpad/v/lib/python3.12/site-packages/pcapy.cpython-312-x86_64-linux-gnu.so` |
| load average at start | 2.88 2.26 1.95 |
| capture | 400000 packets, 175.2 MiB, avg 443 B/packet |
| capture mix | 388066 IPv4, 11934 IPv6, 7860 VLAN-tagged, 23620 distinct flow keys |

## Raw API overhead (NOT equal work)

These three APIs do different amounts of work per packet, so this table is about per-call overhead only, not about who is "faster" at the same job. `next()` and `loop()` build a header object and a bytes object per packet; `next_batch(..._meta)` builds two objects per *batch* and only parses the metadata; `next_batch(..._slice)` adds one bytes object per packet so it delivers the same thing `next()` does.

| scenario | wall median (s) | spread | processed/s | delivered to Python/s | CPU (s) | peak RSS (MiB) | admitted | dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `raw_next` | 0.2344 | ±3.7% | 1,706,360 | 1,706,360 | 0.234 | 130.9 | 400000 | 0 |
| `raw_loop` | 0.1430 | ±29.5% | 2,796,969 | 2,796,969 | 0.143 | 130.9 | 400000 | 0 |
| `raw_next_batch_32_meta` | 0.1492 | ±25.4% | 2,680,086 | 0 | 0.149 | 130.9 | 400000 | 0 |
| `raw_next_batch_32_slice` | 0.1970 | ±3.6% | 2,030,878 | 2,030,878 | 0.197 | 130.9 | 400000 | 0 |
| `raw_next_batch_128_meta` | 0.1409 | ±7.7% | 2,839,053 | 0 | 0.141 | 130.9 | 400000 | 0 |
| `raw_next_batch_128_slice` | 0.1882 | ±2.4% | 2,124,959 | 2,124,959 | 0.188 | 130.9 | 400000 | 0 |
| `raw_next_batch_512_meta` | 0.1405 | ±2.9% | 2,847,134 | 0 | 0.140 | 130.9 | 400000 | 0 |
| `raw_next_batch_512_slice` | 0.1909 | ±5.0% | 2,095,635 | 2,095,635 | 0.191 | 130.9 | 400000 | 0 |
| `raw_next_batch_1024_meta` | 0.1425 | ±8.1% | 2,807,836 | 0 | 0.142 | 130.9 | 400000 | 0 |
| `raw_next_batch_1024_slice` | 0.1942 | ±7.5% | 2,059,773 | 2,059,773 | 0.194 | 130.9 | 400000 | 0 |

## Classification (equal work: C classifier vs Python equivalent)

Each `cls_*` row has a `py_*` counterpart that reaches the same admitted set in Python on top of the classic API. The harness asserts the admitted counts match before any comparison is drawn.

| scenario | wall median (s) | spread | processed/s | delivered to Python/s | CPU (s) | peak RSS (MiB) | admitted | dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `cls_admit_all` | 0.1525 | ±11.5% | 2,623,516 | 2,623,516 | 0.152 | 130.9 | 400000 | 0 |
| `py_admit_all` | 0.5630 | ±4.8% | 710,438 | 710,438 | 0.563 | 130.9 | 400000 | 0 |
| `cls_addrset_50pct` | 0.1146 | ±6.3% | 3,489,847 | 1,745,107 | 0.115 | 130.9 | 200021 | 199979 |
| `py_addrset_50pct` | 0.6002 | ±3.7% | 666,400 | 666,400 | 0.600 | 130.9 | 200021 | 199979 |
| `cls_addrset_10pct` | 0.0691 | ±9.6% | 5,786,240 | 582,674 | 0.069 | 130.9 | 40280 | 359720 |
| `py_addrset_10pct` | 0.6077 | ±1.2% | 658,234 | 658,234 | 0.608 | 130.9 | 40280 | 359720 |
| `cls_addrset_1pct` | 0.0549 | ±6.1% | 7,283,987 | 91,887 | 0.055 | 130.9 | 5046 | 394954 |
| `py_addrset_1pct` | 0.5929 | ±6.0% | 674,658 | 674,658 | 0.593 | 130.9 | 5046 | 394954 |
| `cls_addrset_0pct` | 0.0584 | ±10.7% | 6,844,751 | 0 | 0.058 | 130.9 | 0 | 400000 |
| `py_addrset_0pct` | 0.6064 | ±4.0% | 659,623 | 659,623 | 0.606 | 130.9 | 0 | 400000 |
| `cls_admit_none` | 0.0495 | ±7.8% | 8,085,182 | 0 | 0.049 | 130.9 | 0 | 400000 |
| `py_admit_none` | 0.5659 | ±6.5% | 706,890 | 706,890 | 0.566 | 130.9 | 0 | 400000 |
| `cls_flowheads_1` | 0.0879 | ±9.5% | 4,548,354 | 289,696 | 0.088 | 130.9 | 25477 | 374523 |
| `py_flowheads_1` | 0.8383 | ±6.5% | 477,131 | 477,131 | 0.838 | 130.9 | 23620 | 376380 |
| `cls_flowheads_3` | 0.0945 | ±20.9% | 4,234,171 | 683,109 | 0.094 | 130.9 | 64533 | 335467 |
| `py_flowheads_3` | 0.7797 | ±5.1% | 513,025 | 513,025 | 0.779 | 130.9 | 61825 | 338175 |
| `cls_setsize_seq_10` | 0.0570 | ±5.4% | 7,016,063 | 193,239 | 0.057 | 130.9 | 11017 | 388983 |
| `py_setsize_seq_10` | 0.5992 | ±5.8% | 667,579 | 667,579 | 0.599 | 130.9 | 11017 | 388983 |
| `cls_setsize_seq_1000` | 0.0588 | ±4.4% | 6,804,711 | 187,418 | 0.059 | 130.9 | 11017 | 388983 |
| `py_setsize_seq_1000` | 0.6074 | ±3.8% | 658,523 | 658,523 | 0.607 | 130.9 | 11017 | 388983 |
| `cls_setsize_seq_100000` | 0.0615 | ±21.2% | 6,508,063 | 179,248 | 0.061 | 130.9 | 11017 | 388983 |
| `py_setsize_seq_100000` | 0.6256 | ±9.3% | 639,410 | 639,410 | 0.626 | 130.9 | 11017 | 388983 |
| `cls_setsize_seq_1000000` | 0.0822 | ±12.5% | 4,867,613 | 134,066 | 0.082 | 238.9 | 11017 | 388983 |
| `py_setsize_seq_1000000` | 0.6512 | ±13.1% | 614,273 | 614,273 | 0.651 | 239.0 | 11017 | 388983 |
| `cls_setsize_rand_10` | 0.0596 | ±9.3% | 6,715,504 | 184,961 | 0.060 | 130.9 | 11017 | 388983 |
| `py_setsize_rand_10` | 0.5937 | ±6.3% | 673,760 | 673,760 | 0.594 | 130.9 | 11017 | 388983 |
| `cls_setsize_rand_1000` | 0.0653 | ±6.8% | 6,124,087 | 168,672 | 0.065 | 130.9 | 11017 | 388983 |
| `py_setsize_rand_1000` | 0.6141 | ±5.9% | 651,382 | 651,382 | 0.614 | 130.9 | 11017 | 388983 |
| `cls_setsize_rand_100000` | 0.0638 | ±8.4% | 6,274,316 | 172,810 | 0.064 | 130.9 | 11017 | 388983 |
| `py_setsize_rand_100000` | 0.6233 | ±3.0% | 641,701 | 641,701 | 0.623 | 130.9 | 11017 | 388983 |
| `cls_setsize_rand_1000000` | 0.0860 | ±17.3% | 4,650,825 | 128,095 | 0.086 | 238.9 | 11017 | 388983 |
| `py_setsize_rand_1000000` | 0.6545 | ±24.3% | 611,153 | 611,153 | 0.654 | 238.9 | 11017 | 388983 |

## loop_to_buffer (equal work: C vs Python copying into a bytearray)

`loop_to_buffer` writes `[u32 caplen][u8 class][packet]` records with the GIL released; the Python equivalent produces the same records in a preallocated `bytearray` from the classic API.

| scenario | wall median (s) | spread | processed/s | delivered to Python/s | CPU (s) | peak RSS (MiB) | admitted | dropped |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `buf_admit_all` | 0.0646 | ±3.9% | 6,189,041 | 0 | 0.065 | 280.0 | 400000 | 0 |
| `py_buf_admit_all` | 0.8310 | ±5.7% | 481,356 | 481,356 | 0.831 | 280.1 | 400000 | 0 |
| `buf_addrset_10pct` | 0.0595 | ±12.8% | 6,721,820 | 0 | 0.059 | 280.0 | 40280 | 359720 |
| `py_buf_addrset_10pct` | 0.6485 | ±5.1% | 616,852 | 616,852 | 0.648 | 280.2 | 40280 | 359720 |
| `buf_flowheads_3` | 0.0718 | ±28.9% | 5,567,552 | 0 | 0.072 | 288.1 | 64533 | 335467 |
| `py_buf_flowheads_3` | 0.8682 | ±4.8% | 460,741 | 460,741 | 0.868 | 284.5 | 61825 | 338175 |

## Paired speedups

Ratio of Python-equivalent wall time to C wall time, for pairs that admit the same packets. Values below 1.0 mean the C path is *slower* and are reported as such.

| C scenario | Python equivalent | admitted (C / Python) | C wall (s) | Python wall (s) | speedup |
|---|---|---:|---:|---:|---:|
| `cls_admit_all` | `py_admit_all` | 400,000 | 0.1525 | 0.5630 | **3.69x** |
| `cls_addrset_50pct` | `py_addrset_50pct` | 200,021 | 0.1146 | 0.6002 | **5.24x** |
| `cls_addrset_10pct` | `py_addrset_10pct` | 40,280 | 0.0691 | 0.6077 | **8.79x** |
| `cls_addrset_1pct` | `py_addrset_1pct` | 5,046 | 0.0549 | 0.5929 | **10.80x** |
| `cls_addrset_0pct` | `py_addrset_0pct` | 0 | 0.0584 | 0.6064 | **10.38x** |
| `cls_admit_none` | `py_admit_none` | 0 | 0.0495 | 0.5659 | **11.44x** |
| `cls_flowheads_1` | `py_flowheads_1` | 25,477 / 23,620 (+7.86%) | 0.0879 | 0.8383 | **9.53x** |
| `cls_flowheads_3` | `py_flowheads_3` | 64,533 / 61,825 (+4.38%) | 0.0945 | 0.7797 | **8.25x** |
| `cls_setsize_seq_10` | `py_setsize_seq_10` | 11,017 | 0.0570 | 0.5992 | **10.51x** |
| `cls_setsize_seq_1000` | `py_setsize_seq_1000` | 11,017 | 0.0588 | 0.6074 | **10.33x** |
| `cls_setsize_seq_100000` | `py_setsize_seq_100000` | 11,017 | 0.0615 | 0.6256 | **10.18x** |
| `cls_setsize_seq_1000000` | `py_setsize_seq_1000000` | 11,017 | 0.0822 | 0.6512 | **7.92x** |
| `cls_setsize_rand_10` | `py_setsize_rand_10` | 11,017 | 0.0596 | 0.5937 | **9.97x** |
| `cls_setsize_rand_1000` | `py_setsize_rand_1000` | 11,017 | 0.0653 | 0.6141 | **9.40x** |
| `cls_setsize_rand_100000` | `py_setsize_rand_100000` | 11,017 | 0.0638 | 0.6233 | **9.78x** |
| `cls_setsize_rand_1000000` | `py_setsize_rand_1000000` | 11,017 | 0.0860 | 0.6545 | **7.61x** |
| `buf_admit_all` | `py_buf_admit_all` | 400,000 | 0.0646 | 0.8310 | **12.86x** |
| `buf_addrset_10pct` | `py_buf_addrset_10pct` | 40,280 | 0.0595 | 0.6485 | **10.90x** |
| `buf_flowheads_3` | `py_buf_flowheads_3` | 64,533 / 61,825 (+4.38%) | 0.0718 | 0.8682 | **12.08x** |

Where the two admitted counts differ, the reason is the C flow table: it is direct-mapped with eviction, so colliding flows restart their counters and a few percent extra packets are reported as flow heads. The Python equivalent uses an exact dict and is the reference count.

## Where the newer API does NOT help

None: every paired scenario was at least 1.2x faster in C. (This section exists so that regressions and bad cases show up on their own, not only if someone reads the full table.)

## Correctness cross-check

All 48 scenarios admitted the number of packets predicted by the capture manifest (exact match, except the flow-head scenarios where the C table is allowed to admit more; their actual deltas are in the paired table above).
