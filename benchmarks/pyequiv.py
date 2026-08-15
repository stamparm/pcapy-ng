#!/usr/bin/env python3
"""Python equivalents of the pcapy-ng in-C classifier paths.

These exist so the benchmark compares like with like: whenever loop_filtered() /
loop_to_buffer() makes a decision in C, the paired benchmark makes the *same* logical
decision in Python on top of the classic API, and both must arrive at the same admitted
count (the harness asserts this).

The implementations are meant to be what a competent Python author would write: struct
parsing with precomputed offsets, plain sets/dicts, no per-packet allocations beyond what is
needed. They are not deliberately slow, and they are not micro-tuned beyond readability.

Differences from the C classifier that cannot be avoided, and are documented in the report:
  * the C flow table is a fixed ~12 MB hash (~1M entries) with eviction on collision; the
    Python dict grows without bound. On this capture the key count stays well under 1M, so
    both produce identical results, but memory behaviour differs.
"""
import struct

ETH_P_IP = 0x0800
ETH_P_VLAN = 0x8100
ETH_P_QINQ = 0x88A8

_u16 = struct.Struct('!H')
_ipv4_addrs = struct.Struct('!II')
_ports = struct.Struct('!HH')


def parse_ipv4(buf, l2_offset=14):
    """Return (proto, src, dst, sport, dport) for IPv4 frames, else None.

    Mirrors what the C classifier does: skip VLAN tags, require IPv4, read the addresses and
    (for TCP/UDP) the ports out of the L4 header.
    """
    n = len(buf)
    if n < l2_offset:
        return None
    ethertype = _u16.unpack_from(buf, 12)[0]
    off = l2_offset
    while ethertype in (ETH_P_VLAN, ETH_P_QINQ):
        if n < off + 4:
            return None
        ethertype = _u16.unpack_from(buf, off + 2)[0]
        off += 4
    if ethertype != ETH_P_IP:
        return None
    if n < off + 20:
        return None
    vhl = buf[off]
    if (vhl >> 4) != 4:
        return None
    ihl = (vhl & 0x0F) * 4
    if ihl < 20 or n < off + ihl:
        return None
    proto = buf[off + 9]
    src, dst = _ipv4_addrs.unpack_from(buf, off + 12)
    sport = dport = 0
    if proto in (6, 17):
        l4 = off + ihl
        if n >= l4 + 4:
            sport, dport = _ports.unpack_from(buf, l4)
    return proto, src, dst, sport, dport


# --- paired equivalents ------------------------------------------------------------------

def classify_all(reader):
    """Equivalent of loop_filtered(mask=7): classify every packet, admit everything."""
    admitted = 0
    processed = 0
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        parse_ipv4(data)            # same work the C classifier does before admitting
        admitted += 1
    return {'processed': processed, 'admitted': admitted, 'delivered': processed}


def classify_none(reader):
    """Equivalent of loop_filtered(mask=0): classify every packet, admit nothing."""
    processed = 0
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        parse_ipv4(data)
    return {'processed': processed, 'admitted': 0, 'delivered': processed}


def addr_set_match(reader, addr_set):
    """Equivalent of loop_filtered(admit=SET_MATCH, addr_set=...)."""
    admitted = 0
    processed = 0
    contains = addr_set.__contains__
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        r = parse_ipv4(data)
        if r is not None and (contains(r[1]) or contains(r[2])):
            admitted += 1
    return {'processed': processed, 'admitted': admitted, 'delivered': processed}


def flow_heads(reader, cutoff):
    """Equivalent of loop_filtered(admit=FLOW_HEAD, flow_cutoff=N)."""
    admitted = 0
    processed = 0
    seen = {}
    get = seen.get
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        r = parse_ipv4(data)
        if r is None or r[0] not in (6, 17):   # C tracks flows for TCP/UDP only
            continue
        key = (r[1], r[2], r[3], r[4], r[0])
        n = get(key, 0) + 1
        seen[key] = n
        if n <= cutoff:
            admitted += 1
    return {'processed': processed, 'admitted': admitted, 'delivered': processed}


# --- loop_to_buffer equivalents ----------------------------------------------------------
#
# loop_to_buffer writes [u32 caplen LE][u8 class][caplen bytes] records back to back with the
# GIL released. The Python equivalent below produces the same bytes in a preallocated
# bytearray, so the comparison covers the same copy work.

_rec = struct.Struct('<IB')


def buffer_all(reader, buf):
    written = 0
    processed = 0
    pos = 0
    size = len(buf)
    overflow = 0
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        parse_ipv4(data)
        n = len(data)
        if pos + 5 + n > size:
            overflow += 1
            continue
        _rec.pack_into(buf, pos, n, 0)
        buf[pos + 5:pos + 5 + n] = data
        pos += 5 + n
        written += 1
    return {'processed': processed, 'admitted': written, 'delivered': processed,
            'overflow': overflow, 'bytes_used': pos}


def buffer_addr_set(reader, buf, addr_set):
    written = 0
    processed = 0
    pos = 0
    size = len(buf)
    overflow = 0
    contains = addr_set.__contains__
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        r = parse_ipv4(data)
        if r is None or not (contains(r[1]) or contains(r[2])):
            continue
        n = len(data)
        if pos + 5 + n > size:
            overflow += 1
            continue
        _rec.pack_into(buf, pos, n, 2)
        buf[pos + 5:pos + 5 + n] = data
        pos += 5 + n
        written += 1
    return {'processed': processed, 'admitted': written, 'delivered': processed,
            'overflow': overflow, 'bytes_used': pos}


def buffer_flow_heads(reader, buf, cutoff):
    written = 0
    processed = 0
    pos = 0
    size = len(buf)
    overflow = 0
    seen = {}
    get = seen.get
    while True:
        hdr, data = reader.next()
        if hdr is None:
            break
        processed += 1
        r = parse_ipv4(data)
        if r is None or r[0] not in (6, 17):   # C tracks flows for TCP/UDP only
            continue
        key = (r[1], r[2], r[3], r[4], r[0])
        n = get(key, 0) + 1
        seen[key] = n
        if n > cutoff:
            continue
        ln = len(data)
        if pos + 5 + ln > size:
            overflow += 1
            continue
        _rec.pack_into(buf, pos, ln, 1)
        buf[pos + 5:pos + 5 + ln] = data
        pos += 5 + ln
        written += 1
    return {'processed': processed, 'admitted': written, 'delivered': processed,
            'overflow': overflow, 'bytes_used': pos}
