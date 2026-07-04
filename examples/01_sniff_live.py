#!/usr/bin/env python
"""Classic live capture: open a device, set a BPF filter, print a line per packet.

    sudo python 01_sniff_live.py eth0 "tcp port 80 or udp port 53"

(Live capture needs privileges; on Linux that means root or CAP_NET_RAW.)
"""
import sys
import pcapy

SNAPLEN = 65535
PROMISC = True
TIMEOUT_MS = 100


def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else pcapy.lookupdev()
    bpf = sys.argv[2] if len(sys.argv) > 2 else None

    cap = pcapy.open_live(dev, SNAPLEN, PROMISC, TIMEOUT_MS)
    if bpf:
        cap.setfilter(bpf)
    print("listening on %s%s ... (Ctrl-C to stop)" % (dev, " [%s]" % bpf if bpf else ""))

    n = 0
    while True:
        try:
            hdr, data = cap.next()
        except pcapy.PcapError:
            continue
        if hdr is None:
            continue
        sec, usec = hdr.getts()
        n += 1
        print("#%d  %d.%06d  wire=%d cap=%d" % (n, sec, usec, hdr.getlen(), len(data)))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
