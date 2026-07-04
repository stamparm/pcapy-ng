# coding: utf-8
"""Memory-leak hunt for the pcapy-ng C fast path. Runs loop_filtered / loop_to_buffer
thousands of times and asserts resident memory stays flat -- catches leaks in
ipset_build / flowtab_build (12 MB/call!) / port arrays / per-packet header objects.

RAM-SAFE: intended to run under `ulimit -v`. A real per-call leak would blow the cap
(=> killed/MemoryError = test fails loudly) rather than the host.
Exit 0 = stable, 1 = leak/regression. Py2 + Py3."""
import os
import sys
import gc
import socket

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pcapy
import _pcapgen as G

IOCSET = b"".join(socket.inet_aton(x) for x in G.BAD_IPS)
DPI = [80, 8080, 3128, 8000, 8118, 1080]
TLS = [443]
PAGE_KB = os.sysconf("SC_PAGE_SIZE") // 1024 if hasattr(os, "sysconf") else 4


def rss_kb():
    try:
        with open("/proc/self/statm") as f:
            return int(f.read().split()[1]) * PAGE_KB
    except Exception:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss


def make_pcap():
    pkts = []
    for i in range(1000):
        pkts.append(G.dns_packet("h%d.example.com" % (i % 50)))   # admitted (DNS) -> exercises hdr alloc
        pkts.append(G.quicish_packet(sport=40000 + (i % 500)))    # noise / flow-head churn
        if i % 10 == 0:
            pkts.append(G.ioc_packet(G.BAD_IPS[i % 2]))
            pkts.append(G.http_packet())
    return G.temp_pcap(pkts)


def run_filtered(path, iters):
    for _ in range(iters):
        r = pcapy.open_offline(path)
        r.loop_filtered(-1, lambda h, d, c: None, 0xFF, IOCSET, 2, DPI, TLS, 53)  # ioc+flowtab+ports each call
        r.close()


def run_buffer(path, iters):
    buf = bytearray(1 << 22)
    for _ in range(iters):
        r = pcapy.open_offline(path)
        r.loop_to_buffer(-1, buf, 0xFF, IOCSET, 2, DPI, TLS, 53)
        r.close()


def measure(name, fn, path, warm, hot, budget_kb):
    fn(path, warm)
    gc.collect()
    base = rss_kb()
    fn(path, hot)
    gc.collect()
    after = rss_kb()
    delta = after - base
    ok = delta <= budget_kb
    print("  %-18s warm=%d hot=%d  RSS %d->%d KB  delta=%+d KB  budget=%d  %s"
          % (name, warm, hot, base, after, delta, budget_kb, "OK" if ok else "LEAK?!"))
    return ok


def main():
    path = make_pcap()
    try:
        ok = True
        # flowtab is 12 MB/call: if leaked, 400 calls => ~4.8 GB (blows ulimit). Stable => tiny delta.
        ok &= measure("loop_filtered", run_filtered, path, 40, 400, 40000)
        ok &= measure("loop_to_buffer", run_buffer, path, 40, 400, 40000)
        print("RESULT:", "STABLE (no leak)" if ok else "LEAK DETECTED")
        return 0 if ok else 1
    finally:
        os.unlink(path)


if __name__ == "__main__":
    sys.exit(main())
