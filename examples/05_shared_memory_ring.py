#!/usr/bin/env python
"""Worker-pool design: the capture thread classifies + admits in C and writes the kept packets
straight into shared memory (GIL released the whole time); worker processes drain the buffer in
parallel. No per-packet Python on the capture side.

    python 05_shared_memory_ring.py capture.pcap
    sudo python 05_shared_memory_ring.py eth0

Requires Python 3 (multiprocessing.shared_memory). Each record is
[u32 caplen little-endian][u8 class][caplen bytes].
"""
import os
import sys
from multiprocessing import shared_memory, Process
import pcapy

NAMES = ["OTHER", "FLOW_HEAD", "SET_MATCH"]
RING_BYTES = 64 * 1024 * 1024


def consume(shm_name, start, end):
    shm = shared_memory.SharedMemory(name=shm_name)
    mv = memoryview(shm.buf)
    counts = {}
    off = start
    while off < end:
        ln = mv[off] | (mv[off + 1] << 8) | (mv[off + 2] << 16) | (mv[off + 3] << 24)
        cls = mv[off + 4]
        # packet bytes are mv[off+5 : off+5+ln]; here we just tally by class
        counts[cls] = counts.get(cls, 0) + 1
        off += 5 + ln
    del mv
    shm.close()
    print("  worker %d-%d: %s"
          % (start, end, " ".join("%s=%d" % (NAMES[c], n) for c, n in sorted(counts.items()))))


def slot_offsets(buf, written):
    offs = []
    off = 0
    mv = memoryview(buf)
    for _ in range(written):
        offs.append(off)
        ln = mv[off] | (mv[off + 1] << 8) | (mv[off + 2] << 16) | (mv[off + 3] << 24)
        off += 5 + ln
    offs.append(off)
    return offs


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    cap = pcapy.open_offline(arg) if (arg and os.path.exists(arg)) \
        else pcapy.open_live(arg or pcapy.lookupdev(), 65535, True, 100)

    shm = shared_memory.SharedMemory(create=True, size=RING_BYTES)
    try:
        # PRODUCER: keep flow heads + set matches; drop OTHER in C
        admit = (1 << 1) | (1 << 2)
        res = cap.loop_to_buffer(-1, shm.buf, admit, b"", 3)
        written, dropped, overflow, used = res[:4]
        print("producer: wrote %d packets (%.1f MB), dropped %d in C, overflow %d"
              % (written, used / 1e6, dropped, overflow))

        # CONSUMERS: split the filled ring across 4 worker processes
        N = 4
        offs = slot_offsets(shm.buf, written)
        procs = []
        for k in range(N):
            a = offs[written * k // N]
            b = offs[written * (k + 1) // N]
            p = Process(target=consume, args=(shm.name, a, b))
            p.start()
            procs.append(p)
        for p in procs:
            p.join()
    finally:
        shm.close()
        shm.unlink()


if __name__ == "__main__":
    main()
