#!/usr/bin/env python3
"""Deterministic synthetic capture generator for the pcapy-ng benchmarks.

Writes a pcap file plus a JSON manifest describing exactly what is in it: packet and byte
counts, the address sets used by the addr_set benchmarks (with their exact expected match
counts) and the exact expected FLOW_HEAD counts per flow cutoff. The harness uses the
manifest as ground truth, so every benchmark can assert that the C classifier and its Python
equivalent admitted the same packets.

Everything is driven by a fixed seed, so the same arguments always produce byte-identical
output.

    python3 gen_pcap.py --packets 400000 --out data/bench.pcap
"""
import argparse
import json
import os
import random
import struct
import sys

SEED = 20260815

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_VLAN = 0x8100

# Traffic mix (fractions of generated flows / packets)
FRAC_IPV6 = 0.03          # IPv6 packets: always OTHER for the IPv4 classifier
FRAC_VLAN = 0.02          # VLAN-tagged frames: both C and Python must skip the tag


def ip2int(s):
    a, b, c, d = (int(x) for x in s.split('.'))
    return (a << 24) | (b << 16) | (c << 8) | d


def int2bytes(v):
    return struct.pack('!I', v)


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def eth(ethertype, vlan=False):
    hdr = b'\x02\x00\x00\x00\x00\x01' + b'\x02\x00\x00\x00\x00\x02'
    if vlan:
        return hdr + struct.pack('!HHH', ETH_P_VLAN, 0x0064, ethertype)
    return hdr + struct.pack('!H', ethertype)


def ipv4(proto, src, dst, payload):
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 0x1234, 0x4000, 64, proto, 0,
                      int2bytes(src), int2bytes(dst))
    hdr = hdr[:10] + struct.pack('!H', checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, flags, payload, seq=1):
    hdr = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, flags, 8192, 0, 0)
    return hdr + payload


def udp(sport, dport, payload):
    return struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload


def icmp(payload):
    return struct.pack('!BBHHH', 8, 0, 0, 1, 1) + payload


def ipv6_packet(rnd, payload_len):
    src = bytes(rnd.randrange(256) for _ in range(16))
    dst = bytes(rnd.randrange(256) for _ in range(16))
    payload = bytes(payload_len)
    hdr = struct.pack('!IHBB', (6 << 28), len(payload), 17, 64) + src + dst
    return hdr + payload


class PcapWriter(object):
    """Minimal little-endian pcap writer (linktype EN10MB, microsecond resolution)."""

    def __init__(self, path, snaplen=65535):
        self.fh = open(path, 'wb')
        self.fh.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        self.packets = 0
        self.bytes = 0

    def write(self, ts_sec, ts_usec, data):
        self.fh.write(struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data)))
        self.fh.write(data)
        self.packets += 1
        self.bytes += len(data)

    def close(self):
        self.fh.close()


def build_flows(rnd, n_packets):
    """Create a realistic-ish set of flows whose packet counts sum to ~n_packets."""
    internals = [ip2int('10.%d.%d.%d' % (rnd.randrange(256), rnd.randrange(256),
                                         rnd.randrange(1, 255))) for _ in range(500)]
    externals = []
    seen = set()
    while len(externals) < 4000:
        a = rnd.randrange(1, 224)
        if a in (10, 127, 172, 192, 198):        # keep private/test ranges out of the mix
            continue
        v = ip2int('%d.%d.%d.%d' % (a, rnd.randrange(256), rnd.randrange(256),
                                    rnd.randrange(1, 255)))
        if v not in seen:
            seen.add(v)
            externals.append(v)

    flows = []
    total = 0
    while total < n_packets:
        r = rnd.random()
        if r < 0.70:
            proto, sport, dport = 6, rnd.randrange(32768, 60000), rnd.choice(
                [80, 443, 443, 22, 8080, rnd.randrange(1024, 65535)])
        elif r < 0.95:
            proto, sport, dport = 17, rnd.randrange(32768, 60000), rnd.choice(
                [53, 53, 123, 443, rnd.randrange(1024, 65535)])
        else:
            proto, sport, dport = 1, 0, 0

        # heavy tail: most flows are short, a few carry bulk
        q = rnd.random()
        if q < 0.75:
            count = rnd.randrange(2, 12)
        elif q < 0.97:
            count = rnd.randrange(12, 120)
        else:
            count = rnd.randrange(120, 700)
        count = min(count, n_packets - total)
        if count <= 0:
            break

        flows.append({
            'internal': rnd.choice(internals),
            'external': rnd.choice(externals),
            'proto': proto,
            'sport': sport,
            'dport': dport,
            'count': count,
            'bulk': q >= 0.97,
        })
        total += count
    return flows, externals


def generate(path, n_packets):
    rnd = random.Random(SEED)
    flows, externals = build_flows(rnd, n_packets)

    # Interleave the flows: emit packets in a shuffled order, which preserves per-flow
    # ordering statistics while producing a realistically mixed capture.
    order = []
    for idx, f in enumerate(flows):
        order.extend([idx] * f['count'])
    rnd.shuffle(order)

    writer = PcapWriter(path)
    ext_counts = {}                 # external IP -> number of packets it appears in
    flow_seen = {}                  # directional 5-tuple -> packets seen so far
    head_counts = {1: 0, 2: 0, 3: 0, 5: 0}
    n_ipv4 = n_ipv6 = n_vlan = 0
    emitted = [0] * len(flows)

    ts_sec, ts_usec = 1767225600, 0
    for idx in order:
        f = flows[idx]
        i = emitted[idx]
        emitted[idx] += 1
        ts_usec += 7
        if ts_usec >= 1000000:
            ts_usec -= 1000000
            ts_sec += 1

        vlan = rnd.random() < FRAC_VLAN

        if rnd.random() < FRAC_IPV6:
            frame = eth(ETH_P_IPV6, vlan) + ipv6_packet(rnd, rnd.randrange(40, 200))
            writer.write(ts_sec, ts_usec, frame)
            n_ipv6 += 1
            n_vlan += 1 if vlan else 0
            continue

        outbound = (i % 2 == 0)
        src = f['internal'] if outbound else f['external']
        dst = f['external'] if outbound else f['internal']
        sport = f['sport'] if outbound else f['dport']
        dport = f['dport'] if outbound else f['sport']

        if f['bulk'] and i > 3:
            plen = rnd.choice([1400, 1400, 512, 128])     # bulk transfer, mixed sizes
        elif f['proto'] == 6 and i < 3:
            plen = 0                                      # handshake
        else:
            plen = rnd.choice([0, 0, 24, 64, 120, 300, rnd.randrange(0, 700)])
        payload = bytes(plen)

        if f['proto'] == 6:
            flags = 0x02 if i == 0 else (0x12 if i == 1 else (0x18 if plen else 0x10))
            l4 = tcp(sport, dport, flags, payload, seq=i + 1)
        elif f['proto'] == 17:
            l4 = udp(sport, dport, payload)
        else:
            l4 = icmp(payload)

        frame = eth(ETH_P_IP, vlan) + ipv4(f['proto'], src, dst, l4)
        writer.write(ts_sec, ts_usec, frame)
        n_ipv4 += 1
        n_vlan += 1 if vlan else 0

        ext_counts[f['external']] = ext_counts.get(f['external'], 0) + 1

        # The C classifier only tracks flow heads for TCP/UDP (it needs ports for the key),
        # so the ground truth here must do the same.
        if f['proto'] in (6, 17):
            key = (src, dst, sport, dport, f['proto'])
            seen = flow_seen.get(key, 0) + 1
            flow_seen[key] = seen
            for cutoff in head_counts:
                if seen <= cutoff:
                    head_counts[cutoff] += 1

    writer.close()

    # --- address sets with exact expected match counts -----------------------------------
    ranked = sorted(ext_counts.items(), key=lambda kv: (-kv[1], kv[0]))

    def set_for_fraction(target):
        """Pick external IPs (largest first) until their packets reach ~target of the file."""
        want = int(round(target * writer.packets))
        chosen, got = [], 0
        for ip, c in ranked:
            if got >= want:
                break
            chosen.append(ip)
            got += c
        return chosen, got

    sets = {}
    for name, target in (('50pct', 0.50), ('10pct', 0.10), ('1pct', 0.01)):
        ips, matched = set_for_fraction(target)
        sets[name] = {'ips': ips, 'expected_matches': matched,
                      'actual_fraction': matched / float(writer.packets)}
    # A set that matches nothing. Its addresses are drawn at random (not sequentially) so
    # this scenario measures "nothing admitted", not hash-clustering behaviour -- the latter
    # gets its own sweep below.
    absent = random.Random(SEED + 1)
    present = set(ext_counts)
    zero_ips = []
    while len(zero_ips) < 1000:
        v = absent.randrange(1, 0xFFFFFFFF)
        if v not in present:
            zero_ips.append(v)
    sets['0pct'] = {'ips': zero_ips, 'expected_matches': 0, 'actual_fraction': 0.0}

    # Set-size sweep: every set contains the SAME small core of matching addresses and is
    # padded to size with addresses that never appear in the capture, so the match rate is
    # constant and the only variable is how many addresses the set holds.
    #
    # Two paddings, because set size and key distribution are different variables:
    #   'seq'    consecutive addresses (what you get from expanding CIDR blocks) -- the worst
    #            case for a multiplicative hash whose masked bits come from the low octets
    #   'random' uniformly random addresses -- the average case
    core = [ip for ip, _ in ranked[:10]]
    core_matches = sum(ext_counts[ip] for ip in core)
    pad_base = ip2int('198.18.0.0')
    rnd_pad = random.Random(SEED + 2)
    sizes = (10, 1000, 100000, 1000000)

    size_sets = {}
    for size in sizes:
        ips = list(core) + [pad_base + i + 1 for i in range(max(0, size - len(core)))]
        size_sets[str(size)] = {'ips': ips, 'expected_matches': core_matches,
                                'actual_fraction': core_matches / float(writer.packets)}

    pad_random = []
    seen_pad = set(ext_counts)
    while len(pad_random) < max(sizes):
        v = rnd_pad.randrange(1, 0xFFFFFFFF)
        if v not in seen_pad:
            seen_pad.add(v)
            pad_random.append(v)
    size_sets_random = {}
    for size in sizes:
        ips = list(core) + pad_random[:max(0, size - len(core))]
        size_sets_random[str(size)] = {'ips': ips, 'expected_matches': core_matches,
                                       'actual_fraction': core_matches / float(writer.packets)}

    manifest = {
        'seed': SEED,
        'path': os.path.abspath(path),
        'packets': writer.packets,
        'bytes': writer.bytes,
        'avg_packet_size': writer.bytes / float(writer.packets),
        'file_size': os.path.getsize(path),
        'ipv4_packets': n_ipv4,
        'ipv6_packets': n_ipv6,
        'vlan_packets': n_vlan,
        'flows': len(flows),
        'distinct_flow_keys': len(flow_seen),
        'flow_head_counts': {str(k): v for k, v in sorted(head_counts.items())},
        'addr_sets': sets,
        'addr_set_sizes': size_sets,
        'addr_set_sizes_random': size_sets_random,
    }
    with open(path + '.manifest.json', 'w') as fh:
        json.dump(manifest, fh)

    slim = dict(manifest)
    slim['addr_sets'] = {k: {kk: vv for kk, vv in v.items() if kk != 'ips'}
                         for k, v in sets.items()}
    slim['addr_set_sizes'] = {k: {kk: vv for kk, vv in v.items() if kk != 'ips'}
                              for k, v in size_sets.items()}
    slim['addr_set_sizes_random'] = {k: {kk: vv for kk, vv in v.items() if kk != 'ips'}
                                     for k, v in size_sets_random.items()}
    return slim


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--packets', type=int, default=400000)
    ap.add_argument('--out', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                  'data', 'bench.pcap'))
    args = ap.parse_args()

    outdir = os.path.dirname(os.path.abspath(args.out))
    if not os.path.isdir(outdir):
        os.makedirs(outdir)

    slim = generate(args.out, args.packets)
    json.dump(slim, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write('\n')


if __name__ == '__main__':
    main()
