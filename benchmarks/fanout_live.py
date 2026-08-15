#!/usr/bin/env python3
"""OPTIONAL live PACKET_FANOUT scaling check -- Linux only, results are hardware dependent.

This is deliberately NOT part of the reproducible offline benchmark. It measures a kernel
feature on live traffic, so the numbers depend on the NIC, the driver, RSS/IRQ affinity, the
traffic actually on the wire during the run and what else the machine is doing. Two runs on
the same box can differ substantially; runs on different boxes are not comparable at all.

What it does: opens N live capture handles on one interface, joins them all to the same
PACKET_FANOUT group, reads each in its own thread for a fixed duration, and reports per-handle
and total packet counts plus libpcap's own drop counters. Compare N=1 against N=2/4/8 to see
whether fanout is buying anything on YOUR hardware with YOUR traffic.

    sudo python3 fanout_live.py eth0 --handles 1,2,4 --seconds 10

Needs root or CAP_NET_RAW. Generate load separately (e.g. iperf3) if the link is idle --
an idle link measures nothing.
"""
from __future__ import division, print_function

import argparse
import json
import platform
import sys
import threading
import time

try:
    import pcapy
except ImportError:
    sys.exit('pcapy-ng is not installed')

SNAPLEN = 65535
TIMEOUT_MS = 100


def capture_worker(dev, group, seconds, idx, results, use_fanout, barrier):
    cap = pcapy.open_live(dev, SNAPLEN, True, TIMEOUT_MS)
    if use_fanout:
        cap.set_fanout(group, pcapy.PACKET_FANOUT_HASH)
    barrier.wait()
    n = 0
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            hdr, _ = cap.next()
        except pcapy.PcapError:
            continue
        if hdr is not None:
            n += 1
    try:
        recv, drop, ifdrop = cap.stats()
    except Exception:
        recv = drop = ifdrop = -1
    results[idx] = {'packets': n, 'pcap_recv': recv, 'pcap_drop': drop, 'pcap_ifdrop': ifdrop}
    cap.close()


def run(dev, handles, seconds, group):
    use_fanout = handles > 1
    results = [None] * handles
    barrier = threading.Barrier(handles + 1)
    threads = [threading.Thread(target=capture_worker,
                                args=(dev, group, seconds, i, results, use_fanout, barrier))
               for i in range(handles)]
    for t in threads:
        t.start()
    barrier.wait()
    t0 = time.time()
    for t in threads:
        t.join()
    wall = time.time() - t0

    total = sum(r['packets'] for r in results)
    return {
        'handles': handles,
        'fanout': use_fanout,
        'seconds': round(wall, 3),
        'total_packets': total,
        'packets_per_s': int(total / wall) if wall else 0,
        'per_handle': results,
        'balance_min_max': (min(r['packets'] for r in results),
                            max(r['packets'] for r in results)),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('device')
    ap.add_argument('--handles', default='1,2,4',
                    help='comma-separated handle counts to try (default 1,2,4)')
    ap.add_argument('--seconds', type=float, default=10.0)
    ap.add_argument('--group', type=lambda x: int(x, 0), default=0x4711)
    ap.add_argument('--json', help='write results to this file')
    args = ap.parse_args()

    if platform.system() != 'Linux':
        sys.exit('PACKET_FANOUT is Linux-only')

    out = {'device': args.device, 'kernel': platform.release(), 'runs': [],
           'warning': 'live capture: hardware, driver, IRQ affinity and the traffic present '
                      'during the run all affect these numbers; not reproducible across '
                      'machines or runs'}
    for h in [int(x) for x in args.handles.split(',')]:
        print('capturing %.0fs with %d handle(s)%s ...'
              % (args.seconds, h, ' (fanout)' if h > 1 else ''), file=sys.stderr)
        r = run(args.device, h, args.seconds, args.group)
        out['runs'].append(r)
        print('  %d packets  %d pkt/s  per-handle min/max %s'
              % (r['total_packets'], r['packets_per_s'], r['balance_min_max']), file=sys.stderr)

    base = out['runs'][0]['packets_per_s'] or 1
    for r in out['runs']:
        r['scaling_vs_first'] = round(r['packets_per_s'] / base, 3)

    text = json.dumps(out, indent=2, sort_keys=True)
    if args.json:
        with open(args.json, 'w') as fh:
            fh.write(text + '\n')
    print(text)


if __name__ == '__main__':
    main()
