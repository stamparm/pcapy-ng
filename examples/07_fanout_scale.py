#!/usr/bin/env python
"""Scale capture past one thread with PACKET_FANOUT (Linux).

A single capture socket is one thread's worth of work. To use more cores on a fat pipe, open
several sockets on the SAME interface, join them all to one kernel fanout group with set_fanout(),
and read each in its own thread. The kernel hashes by flow, so every flow lands on exactly one
socket -- the load is shared and no packet is captured twice.

    sudo python 07_fanout_scale.py eth0 4        # 4 capture threads on eth0

(Live capture needs root or CAP_NET_RAW. PACKET_FANOUT is Linux-only.)
"""
import sys
import threading
import pcapy

SNAPLEN, PROMISC, TIMEOUT_MS = 65535, True, 100


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else pcapy.lookupdev()
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    group = 0x4711                       # any 16-bit id; the same value ties the sockets together
    counts = [0] * n

    def worker(idx):
        cap = pcapy.open_live(dev, SNAPLEN, PROMISC, TIMEOUT_MS)
        cap.set_fanout(group, pcapy.PACKET_FANOUT_HASH)   # join the group; flow-hashed distribution
        while True:
            try:
                hdr, _ = cap.next()
            except pcapy.PcapError:
                continue
            if hdr is not None:
                counts[idx] += 1

    print("capturing on %s across %d fanout sockets ... (Ctrl-C to stop)" % (dev, n))
    for i in range(n):
        t = threading.Thread(target=worker, args=(i,))
        t.daemon = True
        t.start()
    try:
        while True:
            threading.Event().wait(2.0)
            print("per-socket packets: %s  (total %d)" % (counts, sum(counts)))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
