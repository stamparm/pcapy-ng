#!/usr/bin/env python
"""Poll per-class counters from another thread WHILE the capture loop runs.

    sudo python 06_live_stats.py eth0
    python 06_live_stats.py capture.pcap

filtered_stats() is safe to read from a second thread; counters are monotonic so a torn read
is harmless. Useful for a live stats line or to drive an adaptive controller.
"""
import os
import sys
import time
import threading
import pcapy


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    cap = pcapy.open_offline(arg) if (arg and os.path.exists(arg)) \
        else pcapy.open_live(arg or pcapy.lookupdev(), 65535, True, 100)

    def run():
        # touch each admitted packet so the loop takes a moment (offline pcaps are fast)
        cap.loop_filtered(-1, lambda h, d, c: len(d), 7, b"", 4)

    t = threading.Thread(target=run)
    t.start()

    while t.is_alive():
        adm, drop, other, head, sset = cap.filtered_stats()
        sys.stdout.write("\radmitted=%d dropped=%d  other=%d flow_head=%d set_match=%d   "
                         % (adm, drop, other, head, sset))
        sys.stdout.flush()
        time.sleep(0.2)
    t.join()

    final = cap.filtered_stats()
    print("\nfinal: admitted=%d dropped=%d  (other,flow_head,set_match)=%s"
          % (final[0], final[1], final[2:]))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
