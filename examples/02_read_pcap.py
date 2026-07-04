#!/usr/bin/env python
"""Read a saved capture and summarize it (no privileges needed).

    python 02_read_pcap.py capture.pcap
"""
import sys
import pcapy


def main(path):
    cap = pcapy.open_offline(path)
    print("datalink: %d" % cap.datalink())

    count = 0
    octets = 0
    cap_truncated = 0
    while True:
        hdr, data = cap.next()
        if hdr is None:
            break
        count += 1
        octets += hdr.getlen()
        if hdr.getcaplen() < hdr.getlen():
            cap_truncated += 1

    print("packets : %d" % count)
    print("bytes   : %d (wire)" % octets)
    print("snaplen-truncated: %d" % cap_truncated)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python 02_read_pcap.py <file.pcap>")
    main(sys.argv[1])
