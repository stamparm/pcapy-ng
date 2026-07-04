# coding: utf-8
"""Battery of unit tests for the pcapy-ng fast path (loop_filtered, loop_to_buffer,
filtered_stats, next_batch, configurable classifier, IOC set, flow-cutoff) plus the
classic API and adversarial robustness. stdlib unittest; runs on Py2 and Py3.

Run:  python3 -m unittest -v test_fast      (and the same under python2)
"""
import os
import sys
import struct
import socket
import random
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pcapy
import _pcapgen as G

# result-tuple indices: (admitted, dropped, dns, dpi, noise, ioc, head, syn)
ADM, DROP, DNS, DPI, NOISE, IOC, HEAD, SYN = range(8)
# class indices (what the classifier returns / admit_mask bits select)
C_DNS, C_DPI, C_NOISE, C_IOC, C_HEAD, C_SYN = range(6)      # admit-mask bit indices
P_DNS, P_DPI, P_NOISE, P_IOC, P_HEAD, P_SYN = range(100, 106)  # public cls ids handed to the callback
ADMIT_ALL = 0xFF
IOCSET = b"".join(socket.inet_aton(x) for x in G.BAD_IPS)


def run_filtered(packets, admit_mask=ADMIT_ALL, ioc=IOCSET, cutoff=0,
                 dpi=None, tls=None, dns=53, collect=False):
    path = G.temp_pcap(packets)
    try:
        r = pcapy.open_offline(path)
        got = []
        def cb(hdr, data, cls):
            if collect:
                got.append((cls, bytes(data)))
            return None
        res = r.loop_filtered(-1, cb, admit_mask, ioc, cutoff, dpi, tls, dns, 14, 1)  # profile=1
        return res, got
    finally:
        os.unlink(path)


class TestClassification(unittest.TestCase):
    def test_dns_classified(self):
        res, _ = run_filtered([G.dns_packet("example.com")] * 5)
        self.assertEqual(res[DNS], 5)

    def test_dpi_psh_on_http_port(self):
        res, _ = run_filtered([G.http_packet()] * 3)
        self.assertEqual(res[DPI], 3)

    def test_non_psh_http_payload_is_dpi(self):
        # Maltrail inspects HTTP responses too (not always PSH) -> any payload-bearing TCP
        # packet on a watched port is DPI, even without the PSH flag.
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(40000, 80, 0x10, b"x" * 10))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[DPI], 1)
        self.assertEqual(res[NOISE], 0)

    def test_bare_ack_on_http_port_is_noise(self):
        # no payload -> carries no HTTP -> noise (and IOC would catch it if to a trail IP)
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(40000, 80, 0x10, b""))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[NOISE], 1)
        self.assertEqual(res[DPI], 0)

    def test_http_port_off_port_payload_not_dpi(self):
        # payload-bearing TCP on a NON-watched port is not DPI (default capture filter excludes it)
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(40000, 12345, 0x18, b"x" * 10))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[DPI], 0)
        self.assertEqual(res[NOISE], 1)

    def test_quic_bulk_is_noise_without_cutoff(self):
        res, _ = run_filtered([G.quicish_packet()] * 4, cutoff=0)
        self.assertEqual(res[NOISE], 4)
        self.assertEqual(res[HEAD], 0)

    def test_ioc_ip_kept_even_as_udp_noise(self):
        res, _ = run_filtered([G.ioc_packet(G.BAD_IPS[0]), G.ioc_packet(G.BAD_IPS[1])])
        self.assertEqual(res[IOC], 2)
        self.assertEqual(res[NOISE], 0)

    def test_ioc_takes_priority_over_flowhead(self):
        # bad IP on tcp/443 PSH -> still IOC (3), not HEAD(4)
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", G.BAD_IPS[0], G.tcp(5000, 443, 0x10, b"x" * 20))
        res, _ = run_filtered([pkt], cutoff=2)
        self.assertEqual(res[IOC], 1)
        self.assertEqual(res[HEAD], 0)

    def test_dns_over_tcp(self):
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "8.8.8.8", G.tcp(5000, 53, 0x18, b"\x00" * 20))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[DNS], 1)

    def test_ipv6_is_noise(self):
        pkt = G.eth(0x86DD) + G.ipv6(17, "::1", "::2", G.udp(53, 53, b"\x00" * 8))
        res, _ = run_filtered([pkt])
        # classifier is IPv4-only -> treated as noise (and must not crash)
        self.assertEqual(res[ADM] + res[DROP], 1)

    def test_arp_is_noise(self):
        pkt = G.eth(0x0806) + b"\x00" * 28
        res, _ = run_filtered([pkt])
        self.assertEqual(res[NOISE], 1)


class TestAdmitMask(unittest.TestCase):
    def setUp(self):
        self.pkts = [G.dns_packet("a.com"), G.http_packet(), G.quicish_packet(),
                     G.ioc_packet(G.BAD_IPS[0]), G.tls_packet("x.com")]

    def test_admit_none(self):
        res, got = run_filtered(self.pkts, admit_mask=0, cutoff=2, collect=True)
        self.assertEqual(res[ADM], 0)
        self.assertEqual(len(got), 0)
        self.assertEqual(res[DROP], len(self.pkts))

    def test_admit_only_dns(self):
        res, got = run_filtered(self.pkts, admit_mask=(1 << C_DNS), cutoff=2, collect=True)
        self.assertEqual(res[ADM], 1)
        self.assertTrue(all(c == P_DNS for c, _ in got))

    def test_admit_all_default_mask_drops_noise(self):
        # default 27 = DNS|DPI|IOC|HEAD (no noise)
        res, _ = run_filtered(self.pkts, admit_mask=27, cutoff=2)
        self.assertEqual(res[ADM], res[DNS] + res[DPI] + res[IOC] + res[HEAD])

    def test_classification_independent_of_mask(self):
        a, _ = run_filtered(self.pkts, admit_mask=0, cutoff=2)
        b, _ = run_filtered(self.pkts, admit_mask=ADMIT_ALL, cutoff=2)
        self.assertEqual(a[DNS:], b[DNS:])  # class counts identical regardless of admit


class TestConfigurablePorts(unittest.TestCase):
    def test_custom_dns_port(self):
        pkt = G.eth() + G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(5353, 5353, b"\x00" * 10))
        res, _ = run_filtered([pkt], dns=5353)
        self.assertEqual(res[DNS], 1)
        res2, _ = run_filtered([pkt], dns=53)
        self.assertEqual(res2[DNS], 0)

    def test_custom_dpi_ports(self):
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(5000, 8443, 0x18, b"x" * 10))
        res, _ = run_filtered([pkt], dpi=[8443])
        self.assertEqual(res[DPI], 1)
        res2, _ = run_filtered([pkt])  # default ports don't include 8443
        self.assertEqual(res2[DPI], 0)

    def test_custom_tls_ports_for_cutoff(self):
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(5000, 8443, 0x10, b"x" * 10))
        res, _ = run_filtered([pkt], cutoff=2, tls=[8443])
        self.assertEqual(res[HEAD], 1)

    def test_ports_as_tuple(self):
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(5000, 9999, 0x18, b"x" * 10))
        res, _ = run_filtered([pkt], dpi=(9999,))
        self.assertEqual(res[DPI], 1)

    def test_empty_port_lists(self):
        # empty dpi list -> nothing is DPI
        res, _ = run_filtered([G.http_packet()], dpi=[])
        self.assertEqual(res[DPI], 0)

    def test_non_int_ports_raise(self):
        path = G.temp_pcap([G.dns_packet("a.com")])
        try:
            r = pcapy.open_offline(path)
            self.assertRaises(Exception, r.loop_filtered, -1,
                              lambda h, d, c: None, 27, IOCSET, 0, ["nope"], None, 53)
        finally:
            os.unlink(path)


class TestIOCSet(unittest.TestCase):
    def test_empty_ioc(self):
        res, _ = run_filtered([G.ioc_packet(G.BAD_IPS[0])], ioc=b"")
        self.assertEqual(res[IOC], 0)
        self.assertEqual(res[NOISE], 1)

    def test_ioc_under_4_bytes_ignored(self):
        res, _ = run_filtered([G.ioc_packet(G.BAD_IPS[0])], ioc=b"\x01\x02\x03")
        self.assertEqual(res[IOC], 0)

    def test_ioc_src_or_dst_match(self):
        # bad IP as SOURCE
        pkt = G.eth() + G.ipv4(17, G.BAD_IPS[0], "10.0.0.5", G.udp(4444, 5000, b"\x00" * 8))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[IOC], 1)

    def test_many_iocs_hash_set(self):
        ips = ["1.2.3.%d" % i for i in range(1, 200)]
        ioc = b"".join(socket.inet_aton(x) for x in ips)
        pkt = G.eth() + G.ipv4(17, "10.0.0.5", "1.2.3.150", G.udp(5000, 6000, b"\x00" * 8))
        res, _ = run_filtered([pkt], ioc=ioc)
        self.assertEqual(res[IOC], 1)


class TestFlowCutoff(unittest.TestCase):
    def _flow(self, n):
        sport = 50000
        return [G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(sport, 443, 0x10, b"\x00" * 50))
                for _ in range(n)]

    def test_cutoff_keeps_first_n(self):
        res, _ = run_filtered(self._flow(10), cutoff=2)
        self.assertEqual(res[HEAD], 2)
        self.assertEqual(res[NOISE], 8)

    def test_cutoff_zero_disables(self):
        res, _ = run_filtered(self._flow(10), cutoff=0)
        self.assertEqual(res[HEAD], 0)
        self.assertEqual(res[NOISE], 10)

    def test_cutoff_one(self):
        res, _ = run_filtered(self._flow(5), cutoff=1)
        self.assertEqual(res[HEAD], 1)


class TestFilteredStats(unittest.TestCase):
    def test_stats_match_return(self):
        pkts = [G.dns_packet("a.com"), G.http_packet(), G.ioc_packet(G.BAD_IPS[0])]
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            self.assertEqual(tuple(r.filtered_stats()), tuple(res))
        finally:
            os.unlink(path)

    def test_stats_reset_between_runs(self):
        path = G.temp_pcap([G.dns_packet("a.com")] * 4)
        try:
            r = pcapy.open_offline(path)
            r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            r2 = pcapy.open_offline(path)
            r2.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            self.assertEqual(r2.filtered_stats()[DNS], 4)  # not 8
        finally:
            os.unlink(path)

    def test_stats_live_from_other_thread(self):
        pkts = [G.dns_packet("a.com")] * 2000
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            samples = []
            def busy(h, d, c):
                # touch data so the loop takes measurable time
                _ = sum(bytearray(d[:4]))
                return None
            def run():
                r.loop_filtered(-1, busy, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            t = threading.Thread(target=run)
            t.start()
            while t.is_alive():
                samples.append(r.filtered_stats()[ADM])
            t.join()
            final = r.filtered_stats()
            self.assertEqual(final[DNS], 2000)
            # counters never decreased
            self.assertEqual(samples, sorted(samples))
        finally:
            os.unlink(path)


class TestLoopToBuffer(unittest.TestCase):
    def _decode(self, buf, n):
        out = []
        off = 0
        mv = bytearray(buf)
        for _ in range(n):
            ln = mv[off] | (mv[off+1] << 8) | (mv[off+2] << 16) | (mv[off+3] << 24)
            cls = mv[off+4]
            out.append((cls, bytes(mv[off+5:off+5+ln])))
            off += 5 + ln
        return out, off

    def test_writes_admitted_only(self):
        pkts = [G.dns_packet("a.com"), G.http_packet(), G.quicish_packet()]
        path = G.temp_pcap(pkts)
        try:
            buf = bytearray(1 << 20)
            r = pcapy.open_offline(path)
            res = r.loop_to_buffer(-1, buf, 27, IOCSET, 0, None, None, 53, 14, 1)  # cutoff 0 -> quic stays noise, dropped
            written, dropped, overflow, used = res[:4]
            self.assertEqual(written, 2)  # dns + dpi; quic noise dropped
            self.assertEqual(overflow, 0)
            decoded, consumed = self._decode(buf, written)
            self.assertEqual(consumed, used)
            self.assertEqual(set(c for c, _ in decoded), set([P_DNS, P_DPI]))
        finally:
            os.unlink(path)

    def test_matches_loop_filtered_counts(self):
        pkts = ([G.dns_packet("a.com")] * 10 + [G.http_packet()] * 5
                + [G.quicish_packet()] * 20 + [G.ioc_packet(G.BAD_IPS[0])] * 3)
        path = G.temp_pcap(pkts)
        try:
            f = pcapy.open_offline(path).loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            buf = bytearray(1 << 21)
            b = pcapy.open_offline(path).loop_to_buffer(-1, buf, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            self.assertEqual(b[4:], f[2:])  # dns,dpi,noise,ioc,head identical
        finally:
            os.unlink(path)

    def test_overflow_is_safe(self):
        # tiny buffer; many admitted -> overflow>0, used<=cap, no crash/corruption
        pkts = [G.dns_packet("a.com")] * 1000
        path = G.temp_pcap(pkts)
        try:
            buf = bytearray(200)  # holds only a couple of packets
            r = pcapy.open_offline(path)
            res = r.loop_to_buffer(-1, buf, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            written, dropped, overflow, used = res[:4]
            self.assertEqual(written + overflow, 1000)
            self.assertTrue(used <= len(buf))
            self.assertTrue(written >= 1)
        finally:
            os.unlink(path)


class TestNextBatch(unittest.TestCase):
    def test_reads_all(self):
        pkts = [G.dns_packet("a.com")] * 137
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            total = 0
            while True:
                buf, meta = r.next_batch(50)
                if not meta:
                    break
                total += len(meta) // 16  # packed 16-byte records
            self.assertEqual(total, 137)
        finally:
            os.unlink(path)


class TestNextBatchEdge(unittest.TestCase):
    def test_max_n_zero_and_negative_clamp(self):
        pkts = [G.dns_packet("a.com")] * 10
        for mn in (0, -5):
            path = G.temp_pcap(pkts)
            try:
                r = pcapy.open_offline(path)
                buf, meta = r.next_batch(mn)  # clamps internally; must not crash
                self.assertTrue(len(meta) % 16 == 0)
                self.assertTrue(len(meta) // 16 >= 1)
            finally:
                os.unlink(path)

    def test_large_max_n_ok(self):
        pkts = [G.dns_packet("a.com")] * 30
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            total = 0
            while True:
                buf, meta = r.next_batch(10000000)  # 10M -> ~160MB meta alloc, fine under cap
                if not meta:
                    break
                total += len(meta) // 16
            self.assertEqual(total, 30)
        finally:
            os.unlink(path)


class TestSnaplenTruncation(unittest.TestCase):
    """caplen < wire length (snaplen-truncated capture): the C path must use caplen and
    never read past it -> no crash, sane classification."""

    def test_truncated_mid_ip(self):
        full = G.dns_packet("trunc.example.com")
        recs = [(len(full), full[:20]),    # only 20 bytes captured (mid IP header)
                (len(full), full[:14]),    # only L2 captured
                (len(full), full[:36]),    # truncated BEFORE the UDP dest-port field
                (len(full), full)]         # complete
        path = G.temp_pcap_trunc(recs)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            self.assertEqual(res[ADM] + res[DROP], 4)   # all accounted, no crash
            self.assertEqual(res[DNS], 1)               # caplen bound: only the complete one sees port 53
        finally:
            os.unlink(path)

    def test_truncated_to_buffer(self):
        full = G.dns_packet("a.com")
        recs = [(len(full), full[:n]) for n in range(0, len(full), 3)] + [(len(full), full)]
        path = G.temp_pcap_trunc(recs)
        try:
            buf = bytearray(1 << 16)
            r = pcapy.open_offline(path)
            res = r.loop_to_buffer(-1, buf, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            self.assertEqual(res[0] + res[1] + res[2], len(recs))  # written+dropped+overflow
            self.assertTrue(res[3] <= len(buf))
        finally:
            os.unlink(path)


class TestBackCompat(unittest.TestCase):
    def test_three_arg_loop_filtered(self):
        path = G.temp_pcap([G.dns_packet("a.com")] * 3)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL)
            self.assertEqual(res[DNS], 3)
        finally:
            os.unlink(path)

    def test_five_arg_loop_filtered(self):
        path = G.temp_pcap([G.ioc_packet(G.BAD_IPS[0])])
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, 27, IOCSET, 2, None, None, 53, 14, 1)
            self.assertEqual(res[IOC], 1)
        finally:
            os.unlink(path)


class TestErrorHandling(unittest.TestCase):
    def test_callback_exception_propagates(self):
        path = G.temp_pcap([G.dns_packet("a.com")] * 5)
        try:
            r = pcapy.open_offline(path)
            def boom(h, d, c):
                raise ValueError("boom")
            self.assertRaises(ValueError, r.loop_filtered, -1, boom, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
        finally:
            os.unlink(path)

    def test_loop_filtered_on_closed(self):
        path = G.temp_pcap([G.dns_packet("a.com")])
        r = pcapy.open_offline(path)
        r.close()
        os.unlink(path)
        self.assertRaises(Exception, r.loop_filtered, -1, lambda h, d, c: None, ADMIT_ALL)

    def test_bad_callback_type(self):
        path = G.temp_pcap([G.dns_packet("a.com")])
        try:
            r = pcapy.open_offline(path)
            self.assertRaises(Exception, r.loop_filtered, -1, "not callable", ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
        finally:
            os.unlink(path)


class TestRobustness(unittest.TestCase):
    """The C path must NEVER crash on malformed/truncated/garbage packets."""

    def _nasty_packets(self, seed=0):
        random.seed(seed)
        pkts = [b"", b"\x00", b"\xff" * 5, b"\xaa" * 13, b"\xaa" * 14,
                G.eth(), G.eth() + b"\x45", G.eth() + b"\x45\x00\x00\xff",
                G.eth() + G.ipv4(17, "1.2.3.4", "5.6.7.8", b"")[:20],  # truncated mid-ip
                G.eth() + struct.pack("B", 0x4f) + b"\x00" * 5,        # ihl=15, short
                G.eth() + struct.pack("B", 0x40) + b"\x00" * 25,       # ihl=0
                G.eth() + G.ipv4(6, "1.2.3.4", "5.6.7.8", G.tcp(80, 80, 0x18, b""))[:30],
                G.eth(0x86DD) + b"\x60" + b"\x00" * 5]
        for _ in range(2000):
            n = random.randint(0, 80)
            pkts.append(bytes(bytearray(random.getrandbits(8) for _ in range(n))))
        return pkts

    def test_loop_filtered_survives_garbage(self):
        pkts = self._nasty_packets(1)
        res, _ = run_filtered(pkts, admit_mask=ADMIT_ALL, cutoff=2)
        self.assertEqual(res[ADM] + res[DROP], len(pkts))  # all accounted, no crash

    def test_loop_to_buffer_survives_garbage(self):
        pkts = self._nasty_packets(2)
        path = G.temp_pcap(pkts)
        try:
            buf = bytearray(1 << 20)
            r = pcapy.open_offline(path)
            res = r.loop_to_buffer(-1, buf, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
            written, dropped, overflow, used = res[:4]
            self.assertEqual(written + dropped + overflow, len(pkts))
            self.assertTrue(used <= len(buf))
        finally:
            os.unlink(path)

    def test_empty_pcap(self):
        res, _ = run_filtered([])
        self.assertEqual(sum(res), 0)


class TestDatalinkOffset(unittest.TestCase):
    """loop_filtered/loop_to_buffer must classify correctly on non-Ethernet datalinks
    via the l2_offset parameter (LINUX_SLL='any' iface, DLT_RAW)."""

    def _ip_dns(self):  # bare IPv4/UDP/53 (no L2)
        return G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(12345, 53, G.dns_query("sll.example.com")))

    def test_sll_with_offset16(self):
        pkts = [G.sll() + self._ip_dns()] * 5
        path = G.temp_pcap(pkts, linktype=G.DLT_LINUX_SLL)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 16, 1)
            self.assertEqual(res[DNS], 5)
        finally:
            os.unlink(path)

    def test_sll_wrong_offset_misclassifies(self):
        # with the default Ethernet offset (14) on an SLL capture, DNS is NOT detected
        pkts = [G.sll() + self._ip_dns()] * 5
        path = G.temp_pcap(pkts, linktype=G.DLT_LINUX_SLL)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)  # default l2=14
            self.assertEqual(res[DNS], 0)  # proves the offset matters (and no crash)
        finally:
            os.unlink(path)

    def test_raw_ip_offset0(self):
        pkts = [self._ip_dns()] * 4
        path = G.temp_pcap(pkts, linktype=G.DLT_RAW)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 0, 1)
            self.assertEqual(res[DNS], 4)
        finally:
            os.unlink(path)

    def test_sll_ioc_and_buffer(self):
        ip = G.ipv4(17, "10.0.0.5", G.BAD_IPS[0], G.udp(4444, 5000, b"\x00" * 8))
        pkts = [G.sll() + ip] * 3
        path = G.temp_pcap(pkts, linktype=G.DLT_LINUX_SLL)
        try:
            buf = bytearray(1 << 16)
            r = pcapy.open_offline(path)
            res = r.loop_to_buffer(-1, buf, ADMIT_ALL, IOCSET, 0, None, None, 53, 16, 1)
            # loop_to_buffer tuple: (written,dropped,overflow,used,dns,dpi,noise,ioc,head)
            self.assertEqual(res[7], 3)  # ioc count
        finally:
            os.unlink(path)

    def test_vlan_single_tag_autoskip(self):
        # default Ethernet l2=14; one 802.1Q tag -> classifier auto-skips to IP at 18
        ip = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(1, 53, G.dns_query("vlan.example.com")))
        pkts = [G.eth_vlan() + ip] * 5
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)  # default l2=14
            self.assertEqual(res[DNS], 5)
        finally:
            os.unlink(path)

    def test_vlan_double_tag_qinq(self):
        ip = G.ipv4(17, "10.0.0.5", "8.8.8.8", G.udp(1, 53, G.dns_query("qinq.example.com")))
        pkts = [G.eth_vlan(tags=2) + ip] * 3
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            self.assertEqual(res[DNS], 3)
        finally:
            os.unlink(path)

    def test_vlan_ioc_sip_correct_after_skip(self):
        # IOC match must use the VLAN-resolved IP offset (sip/dip), not the base offset
        ip = G.ipv4(17, G.BAD_IPS[0], "10.0.0.5", G.udp(4444, 5000, b"\x00" * 8))
        pkts = [G.eth_vlan() + ip] * 2
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 0, None, None, 53, 14, 1)
            self.assertEqual(res[IOC], 2)
        finally:
            os.unlink(path)

    def test_l2_offset_out_of_range(self):
        path = G.temp_pcap([G.dns_packet("a.com")])
        try:
            r = pcapy.open_offline(path)
            self.assertRaises(ValueError, r.loop_filtered, -1, lambda h, d, c: None,
                              ADMIT_ALL, IOCSET, 0, None, None, 53, 999)
        finally:
            os.unlink(path)


class TestSoundSuperset(unittest.TestCase):
    """Gaps closed so the classifier is a sound superset of Maltrail _process_packet:
    SYN admitted (heuristics), and IOC matches ANY IPv4 protocol incl ICMP."""

    def test_pure_syn_classified(self):
        res, _ = run_filtered([G.syn_packet()] * 5)
        self.assertEqual(res[SYN], 5)
        self.assertEqual(res[NOISE], 0)

    def test_syn_any_port_counted(self):
        # SYN to an arbitrary port (not a DPI port) must still be SYN (scan heuristics count all)
        res, _ = run_filtered([G.syn_packet(dport=33333)])
        self.assertEqual(res[SYN], 1)

    def test_syn_ack_not_syn_class(self):
        # SYN+ACK (0x12) is not pure SYN -> not class 5 (handled by IP path / IOC instead)
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "1.2.3.4", G.tcp(40000, 80, 0x12, b""))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[SYN], 0)
        self.assertEqual(res[NOISE], 1)

    def test_icmp_to_trail_ip_is_ioc(self):
        res, _ = run_filtered([G.icmp_packet(G.BAD_IPS[0])] * 3)
        self.assertEqual(res[IOC], 3)        # ICMP to bad IP kept (was missed before)
        self.assertEqual(res[NOISE], 0)

    def test_icmp_non_trail_is_noise(self):
        res, _ = run_filtered([G.icmp_packet("9.9.9.9")])
        self.assertEqual(res[NOISE], 1)
        self.assertEqual(res[IOC], 0)

    def test_icmp_from_trail_ip_is_ioc(self):
        pkt = G.eth() + G.ipv4(1, G.BAD_IPS[1], "10.0.0.5", b"\x00\x00\x00\x00\x00\x00")
        res, _ = run_filtered([pkt])
        self.assertEqual(res[IOC], 1)

    def test_inert_packet_still_dropped(self):
        # plain TCP ACK to a non-trail IP, no PSH/SYN -> truly inert -> noise (safe to drop)
        pkt = G.eth() + G.ipv4(6, "10.0.0.5", "9.9.9.9", G.tcp(40000, 12345, 0x10, b"\x00" * 20))
        res, _ = run_filtered([pkt])
        self.assertEqual(res[NOISE], 1)

    def test_syn_admit_mask(self):
        # SYN dropped when its bit (5) is not in the mask
        res, _ = run_filtered([G.syn_packet()], admit_mask=(1 << C_DNS))
        self.assertEqual(res[ADM], 0)
        self.assertEqual(res[SYN], 1)  # still classified, just not admitted


class TestThreadStress(unittest.TestCase):
    """Concurrent loop_filtered on independent handles must not crash and must classify
    correctly (each handle has its own context; the GIL serializes the Python callbacks)."""

    def test_concurrent_independent_handles(self):
        counts = [0] * 50
        per = [G.dns_packet("a.com")] * 100 + [G.quicish_packet()] * 50
        path = G.temp_pcap(per)
        try:
            errors = []
            def work(idx):
                try:
                    r = pcapy.open_offline(path)
                    res = r.loop_filtered(-1, lambda h, d, c: None, ADMIT_ALL, IOCSET, 2, None, None, 53, 14, 1)
                    counts[idx] = res[DNS]
                except Exception as e:  # noqa
                    errors.append(e)
            ts = [threading.Thread(target=work, args=(i,)) for i in range(8)]
            for t in ts:
                t.start()
            for t in ts:
                t.join()
            self.assertEqual(errors, [])
            self.assertTrue(all(counts[i] == 100 for i in range(8)))
        finally:
            os.unlink(path)


class TestClassicAPI(unittest.TestCase):
    def test_next_loop_dispatch(self):
        pkts = [G.dns_packet("a.com")] * 20
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            n = 0
            while True:
                hdr, data = r.next()
                if hdr is None:
                    break
                n += 1
            self.assertEqual(n, 20)

            r2 = pcapy.open_offline(path)
            c = [0]
            r2.loop(-1, lambda h, d: c.__setitem__(0, c[0] + 1))
            self.assertEqual(c[0], 20)
        finally:
            os.unlink(path)

    def test_setfilter(self):
        pkts = [G.dns_packet("a.com"), G.http_packet(), G.quicish_packet()]
        path = G.temp_pcap(pkts)
        try:
            r = pcapy.open_offline(path)
            r.setfilter("udp port 53")
            c = [0]
            r.loop(-1, lambda h, d: c.__setitem__(0, c[0] + 1))
            self.assertEqual(c[0], 1)
        finally:
            os.unlink(path)

    def test_datalink(self):
        path = G.temp_pcap([G.dns_packet("a.com")])
        try:
            self.assertEqual(pcapy.open_offline(path).datalink(), G.DLT_EN10MB)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
