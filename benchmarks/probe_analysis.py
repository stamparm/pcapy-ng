#!/usr/bin/env python3
"""Probe-behaviour analysis for the C IPv4 address set -- no timing involved.

The set in pcapobj.cc is an open-addressing table with linear probing: `slots[]` sized to the
next power of two >= 2n+1, an index derived from the address, then probe forward until the key
or an empty slot is found. Lookup cost is therefore entirely determined by how well the index
spreads the keys, which can be computed exactly rather than timed.

This script reimplements that table in Python for the old indexing (multiply, then mask the
LOW bits -- which discards the mixing) and the current one (multiply, then take the HIGH bits,
i.e. Fibonacci hashing), and reports probe counts for member and non-member lookups over
sequential (CIDR-like) and random address sets. It is a static analysis: same numbers on any
machine, no benchmark noise.

    python3 probe_analysis.py
"""
from __future__ import division, print_function

import random
import struct
import sys

MASK32 = 0xFFFFFFFF


def to_word(ip):
    """The uint32 the C code actually hashes: memcpy of the 4 network-order bytes on a
    little-endian host, i.e. the byte-swapped dotted-quad value."""
    return struct.unpack('<I', struct.pack('!I', ip))[0]


def index_old(v, mask, bits):
    """As originally implemented: multiply, then mask. The low bits of a product depend only
    on the low bits of the key, so the mixing is thrown away."""
    return ((v * 2654435761) & MASK32) & mask


def index_new(v, mask, bits):
    """As implemented now: multiply, then take the high `bits` (Fibonacci hashing)."""
    return ((v * 2654435761) & MASK32) >> (32 - bits)


def build_table(ips, index):
    n = len(ips)
    cap, bits = 16, 4
    while cap < n * 2 + 1 and bits < 31:
        cap <<= 1
        bits += 1
    slots = [0] * cap
    mask = cap - 1
    worst_insert = 0
    for ip in ips:
        v = to_word(ip)
        if not v:
            continue
        j = index(v, mask, bits)
        p = 1
        while slots[j] and slots[j] != v:
            j = (j + 1) & mask
            p += 1
        slots[j] = v
        worst_insert = max(worst_insert, p)
    return slots, mask, bits, worst_insert


def probe_stats(slots, mask, bits, index, keys):
    """Probes per lookup, counting the initial slot inspection as probe 1."""
    counts = []
    for ip in keys:
        v = to_word(ip)
        j = index(v, mask, bits)
        p = 1
        while slots[j]:
            if slots[j] == v:
                break
            j = (j + 1) & mask
            p += 1
        counts.append(p)
    counts.sort()
    n = len(counts)
    return {
        'mean': sum(counts) / n,
        'median': counts[n // 2],
        'p99': counts[min(n - 1, int(n * 0.99))],
        'max': counts[-1],
    }


def sequential_set(size, base='198.18.0.0'):
    a, b, c, d = (int(x) for x in base.split('.'))
    start = (a << 24) | (b << 16) | (c << 8) | d
    return [start + i for i in range(size)]


def random_set(size, seed=1234):
    rnd = random.Random(seed)
    out, seen = [], set()
    while len(out) < size:
        v = rnd.randrange(1, MASK32)
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out


def main():
    sizes = [int(x) for x in sys.argv[1:]] or [10, 1000, 100000, 1000000]
    rnd = random.Random(99)

    print('%-12s %8s %-6s | %-28s | %-28s'
          % ('distribution', 'entries', 'hash', 'member lookup probes',
             'non-member lookup probes'))
    print('%-12s %8s %-6s | %-28s | %-28s'
          % ('', '', '', 'mean / median / p99 / max', 'mean / median / p99 / max'))
    print('-' * 100)

    for dist, gen in (('sequential', sequential_set), ('random', random_set)):
        for size in sizes:
            ips = gen(size)
            # non-members: addresses that are not in the set, drawn the same way traffic
            # would present them (random source/destination addresses)
            members = set(ips)
            nonmembers = []
            while len(nonmembers) < min(20000, max(1000, size)):
                v = rnd.randrange(1, MASK32)
                if v not in members:
                    nonmembers.append(v)
            probe_members = ips if size <= 20000 else random.Random(7).sample(ips, 20000)

            for label, fn in (('old', index_old), ('new', index_new)):
                slots, mask, bits, _ = build_table(ips, fn)
                m = probe_stats(slots, mask, bits, fn, probe_members)
                nm = probe_stats(slots, mask, bits, fn, nonmembers)
                print('%-12s %8d %-6s | %8.2f %6d %6d %6d | %8.2f %6d %6d %6d'
                      % (dist, size, label, m['mean'], m['median'], m['p99'], m['max'],
                         nm['mean'], nm['median'], nm['p99'], nm['max']))
            print()


if __name__ == '__main__':
    main()
