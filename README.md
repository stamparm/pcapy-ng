## What is Pcapy-NG? ##

[![Build status](https://ci.appveyor.com/api/projects/status/pi4bqe4kgubgr37x?svg=true)](https://ci.appveyor.com/project/CoreSecurity/pcapy)

Pcapy-NG is a Python extension module that lets Python programs use the
[libpcap](https://www.tcpdump.org/) packet-capture library. It is a maintained
replacement for [Pcapy](https://github.com/helpsystems/pcapy), which stopped working
on Python 3.10 ([issue](https://github.com/helpsystems/pcapy/issues/70)), and it works
on both Python 2 and Python 3.

It keeps the classic Pcapy API and adds one thing: **`loop_filtered`**, a capture loop that
does a first pass of filtering *in C* and only hands Python the packets you actually want.

---

## Contents ##

- [Install](#install)
- [Quick start](#quick-start)
- [`loop_filtered`: filtering in C](#loop_filtered-filtering-in-c)
  - [Why not just a BPF filter?](#why-not-just-a-bpf-filter)
  - [Classes and the admit mask](#classes-and-the-admit-mask)
  - [Flow heads: the start of every connection](#flow-heads-the-start-of-every-connection)
  - [Address-set matching](#address-set-matching)
  - [`loop_to_buffer`: filling a shared buffer](#loop_to_buffer-filling-a-shared-buffer)
  - [Live counters and non-Ethernet links](#live-counters-and-non-ethernet-links)
- [Built-in security profile](#built-in-security-profile)
- [API reference](#api-reference)
- [Examples](#examples)
- [Building & compatibility](#building--compatibility)
- [License & credits](#license--credits)

---

## Install ##

```sh
pip install pcapy-ng
```

Pre-built wheels bundle libpcap, so there is nothing to compile at install time. To build
from source you need a C++ compiler and libpcap headers (`libpcap-dev` / `libpcap-devel`):

```sh
python setup.py install        # or: pip install .
```

---

## Quick start ##

```python
import pcapy

print(pcapy.findalldevs())                       # list devices

cap = pcapy.open_live("eth0", 65535, True, 100)  # device, snaplen, promiscuous, timeout(ms)
cap.setfilter("tcp port 80")                     # optional BPF filter (kernel-side)

while True:
    hdr, data = cap.next()
    if hdr is None:
        break
    print(hdr.getts(), hdr.getlen(), len(data))

cap.loop(-1, lambda hdr, data: print(len(data))) # ...or use a callback

cap = pcapy.open_offline("capture.pcap")         # read a saved capture
dumper = cap.dump_open("out.pcap")               # write packets out
```

`hdr` is a `Pkthdr` with `getts()` → `(seconds, microseconds)`, `getlen()` (wire length) and
`getcaplen()` (captured length). This is the original Pcapy surface, unchanged.

---

## `loop_filtered`: filtering in C ##

```python
cap.loop_filtered(cnt, callback, admit_mask=7, addr_set=b"", flow_cutoff=0)
```

`loop_filtered` classifies each packet in C, hands your `callback(hdr, data, cls)` only the
packets you asked for, and drops the rest **without building a Python object for them**. On a
busy link where most traffic is bulk you don't care about, that per-packet object + callback
cost is the thing that makes a pure-Python sniffer fall behind; this avoids paying it.

### Why not just a BPF filter? ###

Fair question — and for a lot of cases the answer is "use BPF." `setfilter("udp port 53")`
runs in the **kernel** and is the right tool for stateless port/protocol matching. You can
(and should) keep using it; `loop_filtered` runs *after* it.

`loop_filtered` exists for the two things a BPF program **can't** do, because BPF is stateless
and size-limited:

1. **Flow state** — "give me the first N packets of each connection, drop the rest." BPF can't
   track flows. This is how you grab the *start* of every conversation (where the useful bytes
   are) while ignoring the bulk that follows.
2. **Large set membership** — "deliver packets whose source or destination is in this set of
   addresses," where the set has thousands or millions of entries. That won't fit in a BPF
   program; here it's an O(1) hash lookup.

If you only need stateless port/proto matching, use BPF. Reach for `loop_filtered` when you
need flow state or set membership (and you can combine both with a BPF prefilter).

### Classes and the admit mask ###

Each delivered packet comes with a small integer `cls` saying why it was kept:

| `cls` | Name | Meaning |
|------|------|---------|
| `0` | `OTHER` | didn't match `flow_cutoff` or `addr_set` |
| `1` | `FLOW_HEAD` | within the first `flow_cutoff` packets of its flow |
| `2` | `SET_MATCH` | source or destination is in `addr_set` |

Classes are **mutually exclusive** — each packet gets exactly one `cls` and increments exactly
one counter. When a packet could be more than one, precedence is **`SET_MATCH` > `FLOW_HEAD` >
`OTHER`** (a flow's first packet that is also a set hit is reported as `SET_MATCH`).

`admit_mask` is a bitmask **over the class number** — bit `cls` admits that class; the rest are
dropped in C. Default `7` (= `1<<0 | 1<<1 | 1<<2`) admits all three, so a bare `loop_filtered`
behaves like `loop` but tagged + counted. To keep only flow heads and set matches, drop `OTHER`:

```python
OTHER, FLOW_HEAD, SET_MATCH = 0, 1, 2
admit = (1 << FLOW_HEAD) | (1 << SET_MATCH)
stats = cap.loop_filtered(-1, my_cb, admit, addr_set, flow_cutoff=3)
# stats -> (admitted, dropped, n_other, n_flow_head, n_set_match)
```

The return value is `(admitted, dropped, <count per class>)`. The per-class counts are
independent of `admit_mask`, so `admit_mask=0` profiles your traffic with no Python work at all.

### Flow heads: the start of every connection ###

`flow_cutoff=N` delivers the first `N` packets of each flow (TCP **and** UDP) as `FLOW_HEAD`
and lets you ignore the rest. The opening packets of a connection are where the interesting
metadata lives — the requested hostname inside a TLS handshake, the first request line, the
greeting of a text protocol — so this captures that and sheds the bulk payload after it.

```python
def on_head(hdr, data, cls):
    # data is the start of a connection; parse out whatever you need (e.g. the TLS server name)
    print("connection start:", len(data), "bytes")
cap.loop_filtered(-1, on_head, (1 << 1), flow_cutoff=3)   # FLOW_HEAD only
```

**What "flow" means here.** A flow is keyed by the **directional** 5-tuple
`(src, dst, src_port, dst_port, protocol)` — so the two directions of a connection are two
flows, and `flow_cutoff=N` yields up to `N` packets *per direction*. There is no TCP-state
tracking (it counts packets per key) and no time-based expiry; the flow table is a fixed
~12 MB hash (about 1M entries, allocated only when `flow_cutoff > 0`) that evicts the
least-recently-seen key on collision — so memory is bounded even under high-cardinality UDP,
at the cost of an occasional re-count when a long-idle flow is evicted. IP fragments are not
reassembled (non-first fragments aren't matched as flow heads).

See [`examples/04_flow_heads.py`](examples/04_flow_heads.py).

### Address-set matching ###

`addr_set` is a packed list of IPv4 addresses (4 bytes each, network order). Any packet whose
source or destination is in it is delivered as `SET_MATCH`, regardless of port or protocol — a
fast way to watch for traffic to/from a set of hosts (an allowlist, a blocklist, an asset
inventory…). The set can be huge.

**IPv4 only.** The classifier operates on IPv4; IPv6 packets are always `OTHER` and never match
`addr_set`. (`setfilter("ip6 ...")` still works for plain IPv6 capture.)

```python
import socket
watch = ["198.51.100.10", "203.0.113.7"]
addr_set = b"".join(socket.inet_aton(ip) for ip in watch)
cap.loop_filtered(-1, on_match, (1 << 2), addr_set)       # SET_MATCH only
```

### `loop_to_buffer`: filling a shared buffer ###

Same classification, but instead of calling Python per packet it writes the admitted packets
**into a writable buffer you provide**, with the GIL released for the whole loop. Pair it with
`multiprocessing.shared_memory` and a pool of workers when one thread isn't enough.

```python
from multiprocessing import shared_memory
shm = shared_memory.SharedMemory(create=True, size=64 * 1024 * 1024)
res = cap.loop_to_buffer(-1, shm.buf, addr_set=addr_set, flow_cutoff=3)
# res -> (written, dropped, overflow, bytes_used, <count per class>)
```

Each record is `[u32 caplen little-endian][u8 class][caplen bytes]`, written back-to-back with
**no padding/alignment**. The only metadata stored is the caplen and the class — **no timestamp
and no wire length**; if you need those, use `loop_filtered` (its callback gets the full
`Pkthdr`). When the buffer fills, extra packets are counted in `overflow` instead of overrunning
it. See [`examples/05_shared_memory_ring.py`](examples/05_shared_memory_ring.py).

### Live counters and non-Ethernet links ###

`filtered_stats()` returns the current run's `(admitted, dropped, <per class>)` counters and is
safe to read from another thread while the loop runs.

`loop_filtered` needs to know where the IPv4 header starts, via `l2_offset`: `14` for Ethernet
(default), `16` for Linux "cooked" capture (`DLT_LINUX_SLL`, the `any` device), `0` for raw IP
(`DLT_RAW`). VLAN tags are skipped automatically. Derive it from `cap.datalink()`:

```python
OFFSETS = {pcapy.DLT_EN10MB: 14, pcapy.DLT_LINUX_SLL: 16, pcapy.DLT_RAW: 0}
cap.loop_filtered(-1, cb, l2_offset=OFFSETS.get(cap.datalink(), 14))
```

---

## Built-in security profile ##

`loop_filtered(..., profile=1)` swaps the generic classifier for a built-in one aimed at
security/traffic monitoring — it tags DNS, HTTP, TLS/QUIC handshakes, TCP SYNs and address-set
hits in a single pass, configurable via `dns_port`, `dpi_ports` and `tls_ports`. It exists so
tools like [Maltrail](https://github.com/stamparm/maltrail) can do their triage in C; if you're
not building that kind of tool, ignore it and stay with the generic classes above.

| index | `cls` id | name | meaning |
|------:|---------:|------|---------|
| 0 | `100` | DNS | UDP/TCP on `dns_port` |
| 1 | `101` | HTTP | payload-bearing TCP on a `dpi_ports` port |
| 2 | `102` | OTHER | none of the below (the shed-able bulk) |
| 3 | `103` | ADDR | src/dst in `addr_set` (any protocol, incl. ICMP) |
| 4 | `104` | HANDSHAKE | flow head on a `tls_ports` port (ClientHello / QUIC Initial) |
| 5 | `105` | SYN | bare TCP SYN |

Two numbers, two jobs — this is the part to get right:

- The **`cls` id** delivered to your callback is `100 + index` (so it never collides with the
  generic `0`/`1`/`2`).
- **`admit_mask` is a bitmask over the `index`, not the id.** To admit DNS + ADDR you write
  `(1 << 0) | (1 << 3)` — *not* `1 << 100`. The default mask for this profile is `59`
  (`= 1<<0 | 1<<1 | 1<<3 | 1<<4 | 1<<5`), i.e. everything except `OTHER` (index 2).

The per-class counts in the return tuple are in `index` order
(`admitted, dropped, dns, http, other, addr, handshake, syn`).

---

## API reference ##

**Module:** `open_live(dev, snaplen, promisc, timeout_ms)`, `open_offline(path)`,
`create(dev)`, `findalldevs()`, `lookupdev()`, `compile(...)`, `DLT_*` constants.

**Reader (classic):** `next()` → `(hdr, data)`, `loop(cnt, cb)`, `dispatch(cnt, cb)`,
`setfilter(bpf)`, `datalink()`, `getnet()`, `getmask()`, `getnonblock()/setnonblock()`,
`setdirection(...)`, `stats()` → `(recv, drop, ifdrop)`, `dump_open(path)`,
`sendpacket(data)`, `getfd()`, `close()`. Usable as a context manager.

**Reader (filtering):**

| Method | Purpose |
|--------|---------|
| `loop_filtered(cnt, cb, admit_mask=7, addr_set=b"", flow_cutoff=0, dpi_ports=None, tls_ports=None, dns_port=53, l2_offset=14, profile=0)` | classify in C; call `cb(hdr, data, cls)` only for admitted classes; return `(admitted, dropped, <per-class counts>)` |
| `loop_to_buffer(cnt, buf, ...same...)` | same, but write admitted packets into `buf` with the GIL released |
| `filtered_stats()` | live counter snapshot of the current/last run |
| `next_batch(max_n)` | advanced: read up to `max_n` packets in one call as `(packet_bytes, packed_meta)` |

`cnt = -1`/`0` means "until EOF (offline) or forever (live)".

`next_batch` returns `(packet_bytes, packed_meta)`: `packet_bytes` is all the packets
concatenated, and `packed_meta` is an array of fixed 16-byte records, one per packet, each four
native-endian `uint32`s — `(sec, usec, offset, caplen)` — where `offset`/`caplen` slice the
packet out of `packet_bytes`. An empty `packed_meta` means EOF/timeout.

---

## Examples ##

Runnable, self-contained scripts in [`examples/`](examples/) — each takes a device (live) or a
`.pcap` (offline) as its first argument:

| File | Shows |
|------|-------|
| `01_sniff_live.py` | classic live capture with a BPF filter |
| `02_read_pcap.py` | read a `.pcap` and summarize it |
| `03_filter_in_c.py` | `loop_filtered`: tag + count, drop `OTHER` in C |
| `04_flow_heads.py` | grab the first packets of each connection (`flow_cutoff`) |
| `05_shared_memory_ring.py` | `loop_to_buffer` producer + multiprocess consumers |
| `06_live_stats.py` | poll `filtered_stats()` from another thread |

---

## Building & compatibility ##

Python 2.7 and 3.x; Linux, macOS and Windows (libpcap / Npcap). The filtering methods are
available wherever pcapy-ng is built; code can probe with `hasattr(reader, "loop_filtered")`
and fall back to `loop()`/`next()` on stock Pcapy. Wheels are produced with
[cibuildwheel](https://cibuildwheel.readthedocs.io/) and vendor libpcap, so deployment needs no
compiler or `libpcap-dev`.

---

## License & credits ##

Apache Software License — see [LICENSE](LICENSE). Pcapy-NG is maintained by Miroslav Stampar
(`miroslav@sqlmap.org`) and builds on the original Pcapy by CORE Security. Bug reports, patches
and suggestions welcome.
