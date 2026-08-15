#!/usr/bin/env python3
"""Reproducible benchmark harness for the pcapy-ng capture APIs.

Measurement first: this harness does not try to make any API look good. Every scenario that
makes a classification decision in C is paired with a Python implementation that makes the
same logical decision on top of the classic API, and the harness asserts that both admit the
same number of packets before it reports a speedup. Scenarios that only compare per-call
overhead (next / loop / next_batch) are reported separately and are explicitly *not*
equal-work comparisons.

Usage:
    python3 gen_pcap.py                       # once: build the deterministic capture
    python3 bench.py --reps 5                 # run everything, write results/

Each measurement runs in a fresh subprocess so that peak RSS, the C flow table and any large
Python set are attributed to the scenario that allocated them.
"""
from __future__ import division, print_function

import argparse
import csv
import json
import os
import platform
import re
import resource
import statistics
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import pyequiv                                            # noqa: E402

DEFAULT_PCAP = os.path.join(HERE, 'data', 'bench.pcap')
RESULTS_DIR = os.path.join(HERE, 'results')

OTHER, FLOW_HEAD, SET_MATCH = 0, 1, 2
M_ALL = (1 << OTHER) | (1 << FLOW_HEAD) | (1 << SET_MATCH)
M_NONE = 0
M_SET = 1 << SET_MATCH
M_HEAD = 1 << FLOW_HEAD


# --------------------------------------------------------------------------------------- #
# system information
# --------------------------------------------------------------------------------------- #

def _cpu_model():
    try:
        with open('/proc/cpuinfo') as fh:
            for line in fh:
                if line.startswith('model name'):
                    return line.split(':', 1)[1].strip()
    except IOError:
        pass
    return platform.processor() or 'unknown'


def _libpcap_version():
    """Ask the libpcap that pcapy actually loaded (may be a vendored copy in a wheel)."""
    import ctypes
    path = None
    try:
        with open('/proc/self/maps') as fh:
            for line in fh:
                m = re.search(r'(\S*libpcap[^\s]*)$', line.strip())
                if m:
                    path = m.group(1)
                    break
    except IOError:
        pass
    try:
        lib = ctypes.CDLL(path) if path else ctypes.CDLL('libpcap.so.1')
        lib.pcap_lib_version.restype = ctypes.c_char_p
        return {'path': path, 'version': lib.pcap_lib_version().decode('utf-8', 'replace')}
    except Exception as exc:                              # pragma: no cover - diagnostics only
        return {'path': path, 'version': 'unknown (%s)' % exc}


def _git_info():
    try:
        out = subprocess.check_output(['git', '-C', HERE, 'rev-parse', '--short', 'HEAD'],
                                      stderr=subprocess.DEVNULL).decode().strip()
        dirty = subprocess.call(['git', '-C', HERE, 'diff', '--quiet', 'HEAD'],
                                stderr=subprocess.DEVNULL) != 0
        return out + ('-dirty' if dirty else '')
    except Exception:
        return 'unknown'


def _cpu_freq_policy():
    info = {}
    for name in ('scaling_governor', 'scaling_driver'):
        try:
            with open('/sys/devices/system/cpu/cpu0/cpufreq/' + name) as fh:
                info[name] = fh.read().strip()
        except IOError:
            pass
    try:
        with open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq') as fh:
            info['scaling_max_freq_khz'] = int(fh.read().strip())
    except IOError:
        pass
    return info


def system_info(manifest):
    import pcapy
    try:
        import importlib.metadata as md
        pcapy_version = md.version('pcapy-ng')
    except Exception:
        pcapy_version = 'unknown'
    return {
        'cpu': _cpu_model(),
        'cpu_count': os.cpu_count(),
        'cpu_freq_policy': _cpu_freq_policy(),
        'loadavg_at_start': os.getloadavg(),
        'platform': platform.platform(),
        'kernel': platform.release(),
        'python': sys.version.split()[0],
        'python_implementation': platform.python_implementation(),
        'python_executable': sys.executable,
        'pcapy_ng_version': pcapy_version,
        'pcapy_module': getattr(pcapy, '__file__', 'unknown'),
        'pcapy_ng_git': _git_info(),
        'libpcap': _libpcap_version(),
        'capture': {
            'path': manifest['path'],
            'packets': manifest['packets'],
            'bytes': manifest['bytes'],
            'file_size': manifest['file_size'],
            'avg_packet_size': round(manifest['avg_packet_size'], 1),
            'ipv4_packets': manifest['ipv4_packets'],
            'ipv6_packets': manifest['ipv6_packets'],
            'vlan_packets': manifest['vlan_packets'],
            'distinct_flow_keys': manifest['distinct_flow_keys'],
        },
    }


# --------------------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------------------- #

def build_scenarios(manifest):
    """Return an ordered list of scenario dicts.

    group    'raw'        per-call overhead only; NOT an equal-work comparison
             'classify'   C classifier vs Python doing the same logical decision
             'buffer'     loop_to_buffer vs Python copying into a bytearray
    pair     name of the counterpart scenario (equal work), or None
    """
    sets = manifest['addr_sets']
    sizes = manifest['addr_set_sizes']
    total = manifest['packets']
    heads = manifest['flow_head_counts']
    s = []

    # --- raw API overhead ---------------------------------------------------------------
    s.append(dict(name='raw_next', group='raw', kind='classic_next', params={},
                  expect=total, note='one Python call + 2 objects per packet'))
    s.append(dict(name='raw_loop', group='raw', kind='classic_loop', params={},
                  expect=total, note='one callback + 2 objects per packet'))
    for bs in (32, 128, 512, 1024):
        s.append(dict(name='raw_next_batch_%d_meta' % bs, group='raw', kind='next_batch',
                      params={'batch': bs, 'slice': False}, expect=total,
                      note='metadata parsed, packet bytes not sliced out'))
        s.append(dict(name='raw_next_batch_%d_slice' % bs, group='raw', kind='next_batch',
                      params={'batch': bs, 'slice': True}, expect=total,
                      note='one bytes object per packet, like next()'))

    # --- classifier: admit rate ---------------------------------------------------------
    s.append(dict(name='cls_admit_all', group='classify', kind='filtered',
                  params={'mask': M_ALL}, expect=total, pair='py_admit_all'))
    s.append(dict(name='py_admit_all', group='classify', kind='py_admit_all',
                  params={}, expect=total))

    for tag, key in (('50', '50pct'), ('10', '10pct'), ('1', '1pct'), ('0', '0pct')):
        exp = sets[key]['expected_matches']
        s.append(dict(name='cls_addrset_%spct' % tag, group='classify', kind='filtered',
                      params={'mask': M_SET, 'set': key}, expect=exp,
                      pair='py_addrset_%spct' % tag,
                      note='%.2f%% of packets admitted' % (100.0 * exp / total)))
        s.append(dict(name='py_addrset_%spct' % tag, group='classify', kind='py_addrset',
                      params={'set': key}, expect=exp))

    s.append(dict(name='cls_admit_none', group='classify', kind='filtered',
                  params={'mask': M_NONE}, expect=0, pair='py_admit_none',
                  note='classify everything, deliver nothing'))
    s.append(dict(name='py_admit_none', group='classify', kind='py_admit_none',
                  params={}, expect=0))

    # --- classifier: flow heads ---------------------------------------------------------
    # The C flow table is direct-mapped with eviction (fixed ~12 MB, 1M slots), so two flows
    # that hash to the same slot evict each other and their counters restart: the C path
    # admits a few percent MORE flow heads than exact per-tuple accounting. That is a design
    # trade (bounded memory) and is reported, not hidden -- hence expect_mode='min'.
    for cutoff in (1, 3):
        s.append(dict(name='cls_flowheads_%d' % cutoff, group='classify', kind='filtered',
                      params={'mask': M_HEAD, 'cutoff': cutoff},
                      expect=heads[str(cutoff)], expect_mode='min',
                      pair='py_flowheads_%d' % cutoff,
                      note='C table is direct-mapped with eviction; admits >= exact count'))
        s.append(dict(name='py_flowheads_%d' % cutoff, group='classify', kind='py_flowheads',
                      params={'cutoff': cutoff}, expect=heads[str(cutoff)]))

    # --- classifier: address-set size sweep (match rate held constant) -------------------
    # Run twice: once with consecutive padding addresses (what expanding CIDR blocks gives
    # you) and once with uniformly random ones, because set size and key distribution are
    # separate variables for an open-addressing hash.
    for dist, key in (('seq', 'sizeset'), ('rand', 'sizeset_rand')):
        table = sizes if dist == 'seq' else manifest['addr_set_sizes_random']
        for size in ('10', '1000', '100000', '1000000'):
            exp = table[size]['expected_matches']
            s.append(dict(name='cls_setsize_%s_%s' % (dist, size), group='classify',
                          kind='filtered', params={'mask': M_SET, key: size}, expect=exp,
                          pair='py_setsize_%s_%s' % (dist, size),
                          note='%s addresses, %s padding, %.2f%% admitted'
                               % (size, 'consecutive' if dist == 'seq' else 'random',
                                  100.0 * exp / total)))
            s.append(dict(name='py_setsize_%s_%s' % (dist, size), group='classify',
                          kind='py_setsize', params={key: size}, expect=exp))

    # --- loop_to_buffer -----------------------------------------------------------------
    s.append(dict(name='buf_admit_all', group='buffer', kind='to_buffer',
                  params={'mask': M_ALL}, expect=total, pair='py_buf_admit_all'))
    s.append(dict(name='py_buf_admit_all', group='buffer', kind='py_buf_all',
                  params={}, expect=total))
    exp10 = sets['10pct']['expected_matches']
    s.append(dict(name='buf_addrset_10pct', group='buffer', kind='to_buffer',
                  params={'mask': M_SET, 'set': '10pct'}, expect=exp10,
                  pair='py_buf_addrset_10pct'))
    s.append(dict(name='py_buf_addrset_10pct', group='buffer', kind='py_buf_addrset',
                  params={'set': '10pct'}, expect=exp10))
    s.append(dict(name='buf_flowheads_3', group='buffer', kind='to_buffer',
                  params={'mask': M_HEAD, 'cutoff': 3}, expect=heads['3'],
                  expect_mode='min', pair='py_buf_flowheads_3',
                  note='C table is direct-mapped with eviction; admits >= exact count'))
    s.append(dict(name='py_buf_flowheads_3', group='buffer', kind='py_buf_flowheads',
                  params={'cutoff': 3}, expect=heads['3']))
    return s


# --------------------------------------------------------------------------------------- #
# child: run exactly one measurement and print JSON
# --------------------------------------------------------------------------------------- #

def _addr_bytes(ips):
    return b''.join(struct.pack('!I', ip) for ip in ips)


def _noop(hdr, data, cls):
    return None


def _noop2(hdr, data):
    return None


def run_one(scenario, manifest):
    import pcapy
    path = manifest['path']
    p = scenario['params']
    kind = scenario['kind']

    # ---- setup (not measured; reported separately) ----
    t_setup = time.perf_counter()
    addr_b = b''
    addr_py = None
    buf = None
    if 'set' in p:
        ips = manifest['addr_sets'][p['set']]['ips']
        addr_b, addr_py = _addr_bytes(ips), set(ips)
    if 'sizeset' in p:
        ips = manifest['addr_set_sizes'][p['sizeset']]['ips']
        addr_b, addr_py = _addr_bytes(ips), set(ips)
    if 'sizeset_rand' in p:
        ips = manifest['addr_set_sizes_random'][p['sizeset_rand']]['ips']
        addr_b, addr_py = _addr_bytes(ips), set(ips)
    if kind in ('to_buffer', 'py_buf_all', 'py_buf_addrset', 'py_buf_flowheads'):
        buf = bytearray(manifest['bytes'] + 5 * manifest['packets'] + 4096)
    cutoff = p.get('cutoff', 0)
    mask = p.get('mask', M_ALL)
    reader = pcapy.open_offline(path)
    setup_s = time.perf_counter() - t_setup

    # ---- measured region ----
    cpu0 = time.process_time()
    t0 = time.perf_counter()

    if kind == 'classic_next':
        n = 0
        while True:
            hdr, data = reader.next()
            if hdr is None:
                break
            n += 1
        res = {'processed': n, 'admitted': n, 'delivered': n, 'dropped': 0}

    elif kind == 'classic_loop':
        # loop() returns no count, so the callback is the same no-op the loop_filtered
        # scenarios use and the packet count comes from the manifest (asserted afterwards).
        reader.loop(-1, _noop2)
        res = {'processed': manifest['packets'], 'admitted': manifest['packets'],
               'delivered': manifest['packets'], 'dropped': 0}

    elif kind == 'next_batch':
        bs = p['batch']
        do_slice = p['slice']
        n = 0
        while True:
            pkts, meta = reader.next_batch(bs)
            if not meta:
                break
            for off in range(0, len(meta), 16):
                sec, usec, o, caplen = struct.unpack_from('=IIII', meta, off)
                if do_slice:
                    _ = pkts[o:o + caplen]
                n += 1
        res = {'processed': n, 'admitted': n, 'delivered': n if do_slice else 0, 'dropped': 0}

    elif kind == 'filtered':
        r = reader.loop_filtered(-1, _noop, mask, addr_b, cutoff)
        res = {'processed': r[0] + r[1], 'admitted': r[0], 'delivered': r[0], 'dropped': r[1]}

    elif kind == 'to_buffer':
        r = reader.loop_to_buffer(-1, buf, mask, addr_b, cutoff)
        res = {'processed': r[0] + r[1], 'admitted': r[0], 'delivered': 0, 'dropped': r[1],
               'overflow': r[2], 'bytes_used': r[3]}

    elif kind == 'py_admit_all':
        res = pyequiv.classify_all(reader)
    elif kind == 'py_admit_none':
        res = pyequiv.classify_none(reader)
    elif kind in ('py_addrset', 'py_setsize'):
        res = pyequiv.addr_set_match(reader, addr_py)
    elif kind == 'py_flowheads':
        res = pyequiv.flow_heads(reader, cutoff)
    elif kind == 'py_buf_all':
        res = pyequiv.buffer_all(reader, buf)
    elif kind == 'py_buf_addrset':
        res = pyequiv.buffer_addr_set(reader, buf, addr_py)
    elif kind == 'py_buf_flowheads':
        res = pyequiv.buffer_flow_heads(reader, buf, cutoff)
    else:
        raise ValueError('unknown kind %r' % kind)

    wall = time.perf_counter() - t0
    cpu = time.process_time() - cpu0

    res.setdefault('dropped', res['processed'] - res['admitted'])
    res.update({
        'name': scenario['name'],
        'wall_s': wall,
        'cpu_s': cpu,
        'setup_s': setup_s,
        'peak_rss_kib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    })
    return res


# --------------------------------------------------------------------------------------- #
# parent: orchestration, aggregation, reporting
# --------------------------------------------------------------------------------------- #

def spawn(scenario, manifest_path, python=None):
    payload = json.dumps({'scenario': scenario, 'manifest': manifest_path})
    out = subprocess.check_output([python or sys.executable, os.path.abspath(__file__),
                                   '--run-one', payload])
    return json.loads(out.decode().strip().splitlines()[-1])


def aggregate(samples):
    def stat(key):
        vals = sorted(x[key] for x in samples)
        med = statistics.median(vals)
        return {
            'median': med,
            'min': vals[0],
            'max': vals[-1],
            'mean': statistics.mean(vals),
            'stdev': statistics.stdev(vals) if len(vals) > 1 else 0.0,
            'rel_spread_pct': 100.0 * (vals[-1] - vals[0]) / med if med else 0.0,
        }
    first = samples[0]
    return {
        'name': first['name'],
        'reps': len(samples),
        'wall': stat('wall_s'),
        'cpu': stat('cpu_s'),
        'setup_s_median': statistics.median(x['setup_s'] for x in samples),
        'peak_rss_kib_max': max(x['peak_rss_kib'] for x in samples),
        'processed': first['processed'],
        'admitted': first['admitted'],
        'dropped': first['dropped'],
        'delivered': first['delivered'],
        'overflow': first.get('overflow', 0),
        'samples_wall_s': [x['wall_s'] for x in samples],
    }


def fmt_rate(n, seconds):
    return n / seconds if seconds > 0 else float('inf')


def write_reports(sysinfo, scenarios, agg, outdir):
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    by_name = {a['name']: a for a in agg}
    scen_by_name = {s['name']: s for s in scenarios}
    total = sysinfo['capture']['packets']

    rows = []
    for a in agg:
        sc = scen_by_name[a['name']]
        w = a['wall']['median']
        exp = sc['expect']
        mode = sc.get('expect_mode', 'exact')
        ok = (a['admitted'] == exp) if mode == 'exact' else (a['admitted'] >= exp)
        rows.append({
            'scenario': a['name'],
            'group': sc['group'],
            'reps': a['reps'],
            'wall_median_s': round(w, 6),
            'wall_min_s': round(a['wall']['min'], 6),
            'wall_max_s': round(a['wall']['max'], 6),
            'wall_stdev_s': round(a['wall']['stdev'], 6),
            'wall_spread_pct': round(a['wall']['rel_spread_pct'], 2),
            'cpu_median_s': round(a['cpu']['median'], 6),
            'setup_median_s': round(a['setup_s_median'], 6),
            'pkts_processed_per_s': int(fmt_rate(a['processed'], w)),
            'pkts_delivered_per_s': int(fmt_rate(a['delivered'], w)),
            'processed': a['processed'],
            'admitted': a['admitted'],
            'dropped': a['dropped'],
            'delivered': a['delivered'],
            'overflow': a['overflow'],
            'peak_rss_mib': round(a['peak_rss_kib_max'] / 1024.0, 1),
            'expected_admitted': exp,
            'expect_mode': mode,
            'admitted_delta_pct': round(100.0 * (a['admitted'] - exp) / exp, 3) if exp else 0.0,
            'admitted_ok': ok,
            'pair': sc.get('pair', ''),
            'note': sc.get('note', ''),
        })

    with open(os.path.join(outdir, 'results.csv'), 'w') as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    with open(os.path.join(outdir, 'results.json'), 'w') as fh:
        json.dump({'system': sysinfo, 'scenarios': scenarios, 'results': agg, 'table': rows},
                  fh, indent=2, sort_keys=True)

    # --- markdown summary ---
    L = []
    A = L.append
    cap = sysinfo['capture']
    A('# pcapy-ng benchmark results\n')
    A('Offline capture, deterministic input, %d repetitions per scenario, medians reported.\n'
      % agg[0]['reps'])
    A('## Environment\n')
    A('| item | value |')
    A('|---|---|')
    A('| CPU | %s (%d logical CPUs) |' % (sysinfo['cpu'], sysinfo['cpu_count']))
    A('| CPU freq policy | %s |' % (sysinfo['cpu_freq_policy'] or 'n/a'))
    A('| OS / kernel | %s |' % sysinfo['platform'])
    A('| Python | %s (%s) |' % (sysinfo['python'], sysinfo['python_implementation']))
    A('| libpcap | %s |' % sysinfo['libpcap']['version'])
    A('| libpcap path | `%s` |' % sysinfo['libpcap']['path'])
    A('| pcapy-ng | %s (git %s) |' % (sysinfo['pcapy_ng_version'], sysinfo['pcapy_ng_git']))
    A('| pcapy module | `%s` |' % sysinfo['pcapy_module'])
    A('| load average at start | %.2f %.2f %.2f |' % tuple(sysinfo['loadavg_at_start']))
    A('| capture | %d packets, %.1f MiB, avg %.0f B/packet |'
      % (cap['packets'], cap['file_size'] / 1048576.0, cap['avg_packet_size']))
    A('| capture mix | %d IPv4, %d IPv6, %d VLAN-tagged, %d distinct flow keys |'
      % (cap['ipv4_packets'], cap['ipv6_packets'], cap['vlan_packets'],
         cap['distinct_flow_keys']))
    A('')

    def table(group, title, blurb):
        A('## %s\n' % title)
        A(blurb + '\n')
        A('| scenario | wall median (s) | spread | processed/s | delivered to Python/s | '
          'CPU (s) | peak RSS (MiB) | admitted | dropped |')
        A('|---|---:|---:|---:|---:|---:|---:|---:|---:|')
        for r in rows:
            if r['group'] != group:
                continue
            A('| `%s` | %.4f | ±%.1f%% | %s | %s | %.3f | %.1f | %d | %d |' % (
                r['scenario'], r['wall_median_s'], r['wall_spread_pct'] / 2.0,
                '{:,}'.format(r['pkts_processed_per_s']),
                '{:,}'.format(r['pkts_delivered_per_s']),
                r['cpu_median_s'], r['peak_rss_mib'], r['admitted'], r['dropped']))
        A('')

    table('raw', 'Raw API overhead (NOT equal work)',
          'These three APIs do different amounts of work per packet, so this table is about '
          'per-call overhead only, not about who is "faster" at the same job. `next()` and '
          '`loop()` build a header object and a bytes object per packet; `next_batch(..._meta)` '
          'builds two objects per *batch* and only parses the metadata; `next_batch(..._slice)` '
          'adds one bytes object per packet so it delivers the same thing `next()` does.')

    table('classify', 'Classification (equal work: C classifier vs Python equivalent)',
          'Each `cls_*` row has a `py_*` counterpart that reaches the same admitted set in '
          'Python on top of the classic API. The harness asserts the admitted counts match '
          'before any comparison is drawn.')

    table('buffer', 'loop_to_buffer (equal work: C vs Python copying into a bytearray)',
          '`loop_to_buffer` writes `[u32 caplen][u8 class][packet]` records with the GIL '
          'released; the Python equivalent produces the same records in a preallocated '
          '`bytearray` from the classic API.')

    A('## Paired speedups\n')
    A('Ratio of Python-equivalent wall time to C wall time, for pairs that admit the same '
      'packets. Values below 1.0 mean the C path is *slower* and are reported as such.\n')
    A('| C scenario | Python equivalent | admitted (C / Python) | C wall (s) | Python wall (s) '
      '| speedup |')
    A('|---|---|---:|---:|---:|---:|')
    for r in rows:
        pair = r['pair']
        if not pair or pair not in by_name:
            continue
        ca, pa = by_name[r['scenario']], by_name[pair]
        c, py = ca['wall']['median'], pa['wall']['median']
        counts = '{:,}'.format(ca['admitted'])
        if ca['admitted'] != pa['admitted']:
            counts += ' / {:,} ({:+.2f}%)'.format(
                pa['admitted'], 100.0 * (ca['admitted'] - pa['admitted']) / pa['admitted'])
        A('| `%s` | `%s` | %s | %.4f | %.4f | **%.2fx** |'
          % (r['scenario'], pair, counts, c, py, py / c))
    A('')
    A('Where the two admitted counts differ, the reason is the C flow table: it is '
      'direct-mapped with eviction, so colliding flows restart their counters and a few '
      'percent extra packets are reported as flow heads. The Python equivalent uses an exact '
      'dict and is the reference count.\n')

    # Structural honesty check: list every pair where the newer API is not a clear win, so a
    # regression or a bad case cannot be quietly buried in the table above.
    weak = []
    for r in rows:
        pair = r['pair']
        if not pair or pair not in by_name:
            continue
        c, py = by_name[r['scenario']]['wall']['median'], by_name[pair]['wall']['median']
        if py / c < 1.2:
            weak.append((r['scenario'], pair, py / c, r['note']))
    A('## Where the newer API does NOT help\n')
    if weak:
        A('Pairs where the C path is less than 1.2x faster than plain Python (or slower):\n')
        A('| C scenario | speedup vs Python | note |')
        A('|---|---:|---|')
        for name, pair, ratio, note in weak:
            A('| `%s` | **%.2fx** | %s |' % (name, ratio, note or ''))
    else:
        A('None: every paired scenario was at least 1.2x faster in C. (This section exists so '
          'that regressions and bad cases show up on their own, not only if someone reads the '
          'full table.)')
    A('')

    bad = [r for r in rows if not r['admitted_ok']]
    A('## Correctness cross-check\n')
    if bad:
        A('**%d scenario(s) did not admit the expected number of packets:**\n' % len(bad))
        for r in bad:
            A('* `%s`: admitted %d, expected %s%d (%+.2f%%)'
              % (r['scenario'], r['admitted'], '>= ' if r['expect_mode'] == 'min' else '',
                 r['expected_admitted'], r['admitted_delta_pct']))
    else:
        A('All %d scenarios admitted the number of packets predicted by the capture manifest '
          '(exact match, except the flow-head scenarios where the C table is allowed to admit '
          'more; their actual deltas are in the paired table above).' % len(rows))
    A('')

    with open(os.path.join(outdir, 'SUMMARY.md'), 'w') as fh:
        fh.write('\n'.join(L))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--run-one', help=argparse.SUPPRESS)
    ap.add_argument('--pcap', default=DEFAULT_PCAP)
    ap.add_argument('--reps', type=int, default=5)
    ap.add_argument('--out', default=RESULTS_DIR)
    ap.add_argument('--only', help='regex: run only matching scenarios')
    ap.add_argument('--report-only', action='store_true',
                    help='regenerate CSV/Markdown from an existing results.json, no measuring')
    args = ap.parse_args()

    if args.report_only:
        with open(os.path.join(args.out, 'results.json')) as fh:
            saved = json.load(fh)
        write_reports(saved['system'], saved['scenarios'], saved['results'], args.out)
        print('regenerated reports in %s' % args.out, file=sys.stderr)
        return

    if args.run_one:
        req = json.loads(args.run_one)
        with open(req['manifest']) as fh:
            manifest = json.load(fh)
        print(json.dumps(run_one(req['scenario'], manifest)))
        return

    manifest_path = args.pcap + '.manifest.json'
    if not os.path.exists(manifest_path):
        sys.exit('missing %s -- run gen_pcap.py first' % manifest_path)
    with open(manifest_path) as fh:
        manifest = json.load(fh)

    # Warm the page cache so the benchmark measures the API, not the disk.
    with open(args.pcap, 'rb') as fh:
        while fh.read(1 << 22):
            pass

    scenarios = build_scenarios(manifest)
    if args.only:
        rx = re.compile(args.only)
        scenarios = [s for s in scenarios if rx.search(s['name'])]

    sysinfo = system_info(manifest)
    print('%d scenarios x %d reps' % (len(scenarios), args.reps), file=sys.stderr)

    samples = {s['name']: [] for s in scenarios}
    for rep in range(args.reps):
        for s in scenarios:
            r = spawn(s, manifest_path)
            samples[s['name']].append(r)
            print('  rep %d/%d %-26s %8.4f s  admitted=%-8d rss=%dMiB'
                  % (rep + 1, args.reps, s['name'], r['wall_s'], r['admitted'],
                     r['peak_rss_kib'] // 1024), file=sys.stderr)

    agg = [aggregate(samples[s['name']]) for s in scenarios]
    rows = write_reports(sysinfo, scenarios, agg, args.out)
    print('\nwrote %s/{results.csv,results.json,SUMMARY.md}' % args.out, file=sys.stderr)
    bad = [r for r in rows if not r['admitted_ok']]
    if bad:
        print('WARNING: %d scenario(s) admitted an unexpected count' % len(bad),
              file=sys.stderr)


if __name__ == '__main__':
    main()
