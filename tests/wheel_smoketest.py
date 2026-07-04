#!/usr/bin/env python3
"""Smoke test run against each cibuildwheel-built wheel in an isolated environment.

Confirms the installed wheel (a) imports, (b) reads a pcap via the classic API, and
(c) exposes the fast-path additions (loop_filtered / loop_to_buffer / filtered_stats).
Usage: python wheel_smoketest.py <path-to-pcap>
"""
import sys
import pcapy


def main(pcap_path):
    # classic API still works
    r = pcapy.open_offline(pcap_path)
    count = [0]
    r.loop(-1, lambda hdr, data: count.__setitem__(0, count[0] + 1))
    assert count[0] > 0, "loop() read zero packets from %s" % pcap_path
    print("loop() read %d packets" % count[0])

    # fast-path additions present
    r2 = pcapy.open_offline(pcap_path)
    for name in ("loop_filtered", "loop_to_buffer", "filtered_stats", "next_batch"):
        assert hasattr(r2, name), "missing fast-path method: %s" % name
    print("fast-path API present: loop_filtered, loop_to_buffer, filtered_stats, next_batch")

    # exercise loop_filtered end to end (admit everything so any pcap yields output)
    r3 = pcapy.open_offline(pcap_path)
    seen = [0]
    res = r3.loop_filtered(-1, lambda hdr, data, cls: seen.__setitem__(0, seen[0] + 1), 0xFF)
    assert sum(res) > 0, "loop_filtered classified zero packets"
    print("loop_filtered OK: %r" % (res,))
    print("WHEEL SMOKE TEST PASSED")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "tests/96pings.pcap")
