#!/usr/bin/env python3
"""真实 UDP/TCP DNS 转发、匹配及动态路由生命周期验证。"""
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'packages/l2tp-ipsec-client/src/domain-dns.c'


def wire_name(name):
    return b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0'


def query(name, qtype=1):
    return struct.pack('!6H', 0x1234, 0x100, 1, 0, 0, 0) + wire_name(name) + struct.pack('!HH', qtype, 1)


def recv_exact(sock, size):
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError()
        data += part
    return data


class DnsServer:
    def __init__(self, address, ttl=30):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(('127.0.0.1', self.port))
        self.tcp.listen()
        self.address, self.ttl, self.calls, self.stopping = address, ttl, [], False
        self.handler = None
        self.threads = [threading.Thread(target=self.run, args=(tcp,), daemon=True) for tcp in (False, True)]
        for thread in self.threads:
            thread.start()

    def reply(self, data):
        self.calls.append(data)
        if self.handler:
            return self.handler(data)
        return self.answer(data, self.address, self.ttl)

    @staticmethod
    def answer(data, address, ttl):
        return data[:2] + b'\x81\x80' + struct.pack('!4H', 1, 1, 0, 0) + data[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, ttl, 4) + socket.inet_aton(address)

    def run(self, tcp):
        sock = self.tcp if tcp else self.udp
        sock.settimeout(.1)
        while not self.stopping:
            try:
                if tcp:
                    client, _ = sock.accept()
                    with client:
                        client.settimeout(2)
                        size = struct.unpack('!H', recv_exact(client, 2))[0]
                        reply = self.reply(recv_exact(client, size))
                        client.sendall(struct.pack('!H', len(reply)) + reply)
                else:
                    data, client = sock.recvfrom(65535)
                    sock.sendto(self.reply(data), client)
            except socket.timeout:
                pass
            except (OSError, EOFError):
                if not self.stopping:
                    raise

    def close(self):
        self.stopping = True
        for thread in self.threads:
            thread.join(timeout=3)
        self.udp.close()
        self.tcp.close()


class DomainDnsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.binary = pathlib.Path(cls.build.name) / 'domain-dns'
        import shlex
        subprocess.run(['cc', '-std=c99', '-Wall', '-Wextra', '-Werror', *shlex.split(os.environ.get('TEST_CFLAGS', '')), str(SOURCE), '-o', str(cls.binary)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.vpn = DnsServer('10.20.1.2')
        self.local = DnsServer('192.0.2.10')
        self.trace = self.dir / 'routes'
        self.ip = self.dir / 'ip'
        self.ip.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$TEST_ROUTE_TRACE"\n[ "${TEST_ROUTE_FAIL:-0}" = 0 ]\n')
        self.ip.chmod(0o755)
        self.process = None

    def tearDown(self):
        if self.process:
            self.process.terminate()
            self.process.communicate(timeout=6)
        self.vpn.close()
        self.local.close()
        self.tmp.cleanup()

    def start(self, mode='rules', fail=False, extra=()):
        rules = self.dir / 'rules'
        rules.write_text('exact exact.example.com\nprefix api.\nprefix internal-\nsuffix example.org\n')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        ready = self.dir / 'ready'
        args = [str(self.binary), '--rules', str(rules), '--vpn-dns', '127.0.0.1', '--vpn-port', str(self.vpn.port),
                '--local-dns', '127.0.0.1', '--local-port', str(self.local.port), '--mode', mode,
                '--port', str(self.port), '--ip-tool', str(self.ip), '--ready', str(ready), *extra]
        self.process = subprocess.Popen(args, env={**os.environ, 'TEST_ROUTE_TRACE': str(self.trace), 'TEST_ROUTE_FAIL': str(int(fail))},
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 3
        while not ready.exists() and self.process.poll() is None and time.monotonic() < deadline:
            time.sleep(.01)
        self.assertTrue(ready.exists())

    def ask(self, name, qtype=1, tcp=False):
        data = query(name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
            sock.settimeout(4)
            sock.connect(('127.0.0.1', self.port))
            if tcp:
                sock.sendall(struct.pack('!H', len(data)) + data)
                return recv_exact(sock, struct.unpack('!H', recv_exact(sock, 2))[0])
            sock.send(data)
            return sock.recv(65535)

    def test_or_matching_case_and_boundaries(self):
        self.start()
        for name in ['exact.example.com', 'EXACT.EXAMPLE.COM', 'api.other.net', 'internal-app.net', 'example.org', 'a.example.org']:
            with self.subTest(name=name):
                self.assertEqual(self.ask(name)[-4:], socket.inet_aton(self.vpn.address))
        for name in ['sub.exact.example.com', 'xapi.other.net', 'badexample.org']:
            with self.subTest(name=name):
                self.assertEqual(self.ask(name)[-4:], socket.inet_aton(self.local.address))
        self.assertEqual(len(self.vpn.calls), 6)
        self.assertEqual(len(self.local.calls), 3)
        self.assertIn('replace 10.20.1.2 dev l2tp-vpn table 41717 proto static metric 41718', self.trace.read_text())

    def test_tcp_and_aaaa_https_suppression(self):
        self.start()
        self.assertEqual(self.ask('api.example.net', tcp=True)[-4:], socket.inet_aton(self.vpn.address))
        before = len(self.vpn.calls)
        for qtype in (28, 64, 65, 255):
            answer = self.ask('api.example.net', qtype)
            self.assertEqual(struct.unpack('!H', answer[6:8])[0], 0)
        self.assertEqual(len(self.vpn.calls), before)
        self.assertEqual(self.ask('www.other.net', 28)[-4:], socket.inet_aton(self.local.address))

    def test_full_mode_uses_vpn_without_dynamic_routes(self):
        self.start('full')
        self.assertEqual(self.ask('www.other.net')[-4:], socket.inet_aton(self.vpn.address))
        self.assertFalse(self.trace.exists())
        self.assertEqual(self.ask('www.other.net', 28)[6:8], b'\0\0')

    def test_route_error_is_servfail(self):
        self.start(fail=True)
        self.assertEqual(self.ask('api.test.net')[3] & 15, 2)

    def test_response_validation(self):
        self.start()
        self.vpn.handler = lambda data: b'\xab\xcd' + DnsServer.answer(data, self.vpn.address, 30)[2:]
        self.assertEqual(self.ask('api.test.net')[3] & 15, 2)
        self.assertFalse(self.trace.exists())
        self.vpn.handler = lambda data: data[:2] + b'\x81\x80' + struct.pack('!4H', 1, 1, 0, 0) + data[12:] + b'\xc0\xff'
        self.assertEqual(self.ask('api.test.net')[3] & 15, 2)
        self.assertFalse(self.trace.exists())

    def test_cname_ttl_and_unrelated_answer_ignored(self):
        self.start()
        def reply(data):
            cname = wire_name('target.other.net')
            records = b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 1, len(cname)) + cname
            records += wire_name('target.other.net') + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('10.20.2.3')
            records += wire_name('unrelated.net') + struct.pack('!HHIH', 1, 1, 60, 4) + socket.inet_aton('10.99.2.3')
            return data[:2] + b'\x81\x80' + struct.pack('!4H', 1, 3, 0, 0) + data[12:] + records
        self.vpn.handler = reply
        self.ask('api.test.net')
        trace = self.trace.read_text()
        self.assertIn('replace 10.20.2.3', trace)
        self.assertNotIn('10.99.2.3', trace)
        # TTL 到期后路由仍保留，长连接不会被切断；退出时统一删除
        time.sleep(3.5)
        self.assertNotIn('del 10.20.2.3', self.trace.read_text())
        self.process.terminate()
        self.process.communicate(timeout=5)
        self.process = None
        self.assertIn('del 10.20.2.3', self.trace.read_text())

    def test_full_table_reuses_only_expired_addresses(self):
        addresses = {'api.one.net': '10.20.3.1', 'api.two.net': '10.20.3.2', 'api.three.net': '10.20.3.3'}
        ttls = {'api.one.net': 1, 'api.two.net': 60, 'api.three.net': 60}
        def reply(data):
            name = '.'.join(part.decode() for part in self.labels(data[12:]))
            return DnsServer.answer(data, addresses[name], ttls[name])
        self.vpn.handler = reply
        self.start(extra=('--max-routes', '1'))
        self.assertEqual(self.ask('api.one.net')[-4:], socket.inet_aton('10.20.3.1'))
        time.sleep(3.5)
        self.assertEqual(self.ask('api.two.net')[-4:], socket.inet_aton('10.20.3.2'))
        trace = self.trace.read_text()
        self.assertIn('del 10.20.3.1', trace)
        self.assertIn('replace 10.20.3.2', trace)
        self.assertEqual(self.ask('api.three.net')[3] & 15, 2)
        self.assertNotIn('del 10.20.3.2', self.trace.read_text())

    @staticmethod
    def labels(data):
        while data[0]:
            yield data[1:1 + data[0]]
            data = data[1 + data[0]:]

    def test_malformed_queries_and_slow_tcp_do_not_block_shutdown(self):
        self.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(.2)
            sock.connect(('127.0.0.1', self.port))
            for data in [b'', b'x' * 11, query('api.test.net')[:12] + b'\xc0\x0c',
                         query('api.test.net')[:12] + b'\x3fshort', query('api.test.net')[:4] + b'\x00\x02' + query('api.test.net')[6:]]:
                sock.send(data)
                with self.assertRaises(socket.timeout):
                    sock.recv(65535)
        self.assertEqual(self.ask('api.test.net')[-4:], socket.inet_aton(self.vpn.address))
        with socket.socket() as slow:
            slow.connect(('127.0.0.1', self.port))
            slow.sendall(b'\xff\xffx')
            started = time.monotonic()
            self.process.terminate()
            self.process.communicate(timeout=5)
            self.assertLess(time.monotonic() - started, 4)

    def test_invalid_route_limit_is_rejected(self):
        for value in ('0', '4097', 'x'):
            result = subprocess.run([str(self.binary), '--rules', '/dev/null', '--vpn-dns', '127.0.0.1', '--max-routes', value],
                                    capture_output=True)
            self.assertEqual(result.returncode, 2)

    def test_shutdown_cleans_and_shared_ip_uses_longest_ttl(self):
        self.start()
        self.vpn.ttl = 30
        self.ask('api.one.net')
        self.vpn.ttl = 1
        self.ask('api.two.net')
        time.sleep(4)
        self.assertNotIn('del ', self.trace.read_text())
        self.process.terminate()
        self.process.communicate(timeout=5)
        self.assertIn('del 10.20.1.2', self.trace.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
