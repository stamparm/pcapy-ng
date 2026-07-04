#!/usr/bin/env python
"""Grab the START of every connection and ignore the bulk that follows.

    python 04_flow_heads.py capture.pcap
    sudo python 04_flow_heads.py eth0

flow_cutoff=N delivers the first N packets of each flow (TCP and UDP) as FLOW_HEAD; the rest
is dropped in C. The opening packets are where the useful metadata is. As a concrete example
we read the server name out of a TLS handshake (it travels in the clear, in the first packets
of the connection) -- a thing BPF can't get you, because it needs flow state to know which
packets are "the start".
"""
import os
import sys
import pcapy

FLOW_HEAD = 1
ETH = 14   # IPv4 offset for Ethernet; see README for other link types


def tls_server_name(packet, ip_off=ETH):
    """Return the SNI host from a TLS ClientHello at the start of a flow, or None. Defensive."""
    try:
        b = bytearray(packet)
        ihl = (b[ip_off] & 0x0f) * 4
        l4 = ip_off + ihl
        if b[ip_off + 9] != 6:                     # TCP only
            return None
        rec = l4 + (((b[l4 + 12] >> 4) & 0x0f) * 4)  # TCP payload start
        if len(b) < rec + 43 or b[rec] != 0x16 or b[rec + 5] != 0x01:  # TLS handshake/ClientHello
            return None
        p = rec + 5 + 4 + 2 + 32
        p += 1 + b[p]                               # session id
        p += 2 + ((b[p] << 8) | b[p + 1])           # cipher suites
        p += 1 + b[p]                               # compression
        end = p + 2 + ((b[p] << 8) | b[p + 1]); p += 2
        while p + 4 <= end and p + 4 <= len(b):
            etype = (b[p] << 8) | b[p + 1]; elen = (b[p + 2] << 8) | b[p + 3]; p += 4
            if etype == 0x0000:                     # server_name extension
                np = p + 2 + 1
                nlen = (b[np] << 8) | b[np + 1]
                return bytes(b[np + 2:np + 2 + nlen]).decode("ascii", "replace")
            p += elen
    except Exception:
        return None


def open_source(arg):
    if arg and os.path.exists(arg):
        return pcapy.open_offline(arg)
    return pcapy.open_live(arg or pcapy.lookupdev(), 65535, True, 100)


def main():
    cap = open_source(sys.argv[1] if len(sys.argv) > 1 else None)
    seen = set()

    def on_head(hdr, data, cls):
        name = tls_server_name(bytes(data))
        if name and name not in seen:
            seen.add(name)
            print("server name: %s" % name)

    cap.loop_filtered(-1, on_head, (1 << FLOW_HEAD), b"", 4)   # first 4 pkts of each flow
    print("\n%d unique TLS server name(s) seen" % len(seen))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
