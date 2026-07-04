#!/usr/bin/env python
"""loop_filtered: classify each packet in C, hand Python only what you ask for, drop the rest
without building a Python object.

    python 03_filter_in_c.py capture.pcap
    sudo python 03_filter_in_c.py eth0

Here we keep the start of every connection (FLOW_HEAD) and anything to/from a watch list
(SET_MATCH), and drop the rest (OTHER) in C. At the end we print the class counts and how
much never had to cross into Python.
"""
import os
import sys
import socket
import pcapy

OTHER, FLOW_HEAD, SET_MATCH = 0, 1, 2
NAMES = ["OTHER", "FLOW_HEAD", "SET_MATCH"]

WATCH = ["8.8.8.8", "1.1.1.1"]                      # any address list; can be huge
ADDR_SET = b"".join(socket.inet_aton(ip) for ip in WATCH)


def open_source(arg):
    if arg and os.path.exists(arg):
        return pcapy.open_offline(arg)
    return pcapy.open_live(arg or pcapy.lookupdev(), 65535, True, 100)


def main():
    cap = open_source(sys.argv[1] if len(sys.argv) > 1 else None)
    shown = [0]

    def on_packet(hdr, data, cls):
        if shown[0] < 20:
            print("keep %-9s len=%d" % (NAMES[cls], len(data)))
            shown[0] += 1

    admit = (1 << FLOW_HEAD) | (1 << SET_MATCH)     # drop OTHER in C
    res = cap.loop_filtered(-1, on_packet, admit, ADDR_SET, 3)
    admitted, dropped, n_other, n_head, n_set = res
    total = admitted + dropped
    print("\n--- summary ---")
    print("classes : other=%d flow_head=%d set_match=%d" % (n_other, n_head, n_set))
    if total:
        print("kept %d / %d  (%.1f%% reached Python, %.1f%% dropped in C)"
              % (admitted, total, 100.0 * admitted / total, 100.0 * dropped / total))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
