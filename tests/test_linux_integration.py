#!/usr/bin/env python3
"""在隔离 Linux 容器内验证工作进程生命周期与真实协议配置解析。"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILES = ROOT / 'packages/l2tp-ipsec-client/files'


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.tmp.name)
        self.runtime = self.directory / 'run'
        self.lib = self.directory / 'lib'
        self.bin = self.directory / 'bin'
        self.bin.mkdir()
        shutil.copytree(FILES / 'usr/lib/l2tp-ipsec-client', self.lib)
        self.trace = self.directory / 'trace'
        common = self.lib / 'common.sh'
        with common.open('a') as file:
            file.write('''
lp_load() {
 server=vpn.example.com; username=test; password=test; psk=test
 ike=aes256-sha256-modp2048; esp=aes256-sha1; local_id=; remote_id=
 mtu=1400; lcp_interval=30; lcp_failure=5; retry_interval=10
 probe_ip=; routes=; reconnect=${TEST_RECONNECT:-0}
}
lp_state() { printf '%s|%s\\n' "$1" "$2" >> "$TEST_TRACE"; }
lp_has_ipsec() { [ "${TEST_PHASE:-}" = ppp ]; }
lp_swan() { return 0; }
''')
        worker = (self.lib / 'worker').read_text().replace(
            '. /usr/lib/l2tp-ipsec-client/common.sh', f'. {common}')
        worker = worker.replace('/usr/lib/ipsec/charon', str(self.bin / 'charon'))
        (self.lib / 'worker').write_text(worker)
        self.env = {**os.environ, 'LP_DIR': str(self.runtime), 'LP_LIB': str(self.lib),
                    'TEST_TRACE': str(self.trace), 'PATH': str(self.bin) + ':' + os.environ['PATH']}
        mocks = {
            'resolveip': 'echo 192.0.2.20',
            'pidof': '[ "${TEST_CONFLICT:-0}" = 1 ]',
            'ip': '''case "$*" in
*"route get"*) echo "192.0.2.20 via 172.17.0.1 dev eth0 src 172.17.0.2" ;;
*"route show"*) : ;;
*) printf 'ip %s\\n' "$*" >> "$TEST_TRACE" ;;
esac''',
            'charon': '''python3 -c 'import os,socket,time; s=socket.socket(socket.AF_UNIX); s.bind(os.environ["LP_DIR"]+"/charon.vici"); time.sleep(120)' &
child=$!
trap 'kill "$child" 2>/dev/null; exit 0' TERM INT
wait "$child"''',
            'swanctl': '''if [ "${TEST_PHASE:-}" = ipsec ] && [ "$1" = --initiate ]; then
 printf 'ipsec-wait\\n' >> "$TEST_TRACE"
 sleep 25 &
 child=$!
 trap 'kill "$child" 2>/dev/null; exit 0' TERM INT
 wait "$child"
fi''',
            'xl2tpd': '''mkfifo "$LP_DIR/l2tp-control"
sleep 120 &
child=$!
trap 'kill "$child" 2>/dev/null; exit 0' TERM INT
wait "$child"''',
            'xl2tpd-control': 'exit 0',
        }
        for name, source in mocks.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + source + '\n')
            path.chmod(0o755)
        (self.lib / 'ppp-hook').write_text('#!/bin/sh\nexit 0\n')
        self.process = None

    def tearDown(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=8)
        if self.process:
            self.process.communicate()
        self.tmp.cleanup()

    def start(self, **env):
        self.process = subprocess.Popen(['sh', str(self.lib / 'worker')], env={**self.env, **env},
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def wait_for(self, value):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.trace.exists() and value in self.trace.read_text():
                return
            if self.process.poll() is not None:
                break
            time.sleep(0.05)
        out, err = self.process.communicate(timeout=2) if self.process.poll() is not None else ('', '')
        self.fail(f'没有到达状态 {value}: {out} {err} {self.trace.read_text() if self.trace.exists() else ""}')

    def test_existing_service_conflict_does_not_change_routes(self):
        self.start(TEST_CONFLICT='1')
        self.process.wait(timeout=5)
        trace = self.trace.read_text()
        self.assertIn('conflict|', trace)
        self.assertNotIn('ip xfrm policy add', trace)
        self.assertFalse((self.runtime / 'lock').exists())

    def test_failure_cleans_owned_routes_and_credentials(self):
        self.start()
        self.process.wait(timeout=8)
        trace = self.trace.read_text()
        self.assertIn('error|IPsec 协商失败', trace)
        self.assertIn('ip xfrm policy add', trace)
        self.assertIn('ip xfrm policy delete', trace)
        self.assertIn('ip -4 route del 192.0.2.20/32 metric 41717', trace)
        self.assertFalse((self.runtime / 'swanctl.conf').exists())
        self.assertFalse((self.runtime / 'ppp.options').exists())

    def test_stop_interrupts_ipsec_wait(self):
        self.start(TEST_PHASE='ipsec')
        self.wait_for('ipsec-wait')
        started = time.monotonic()
        self.process.terminate()
        self.process.wait(timeout=7)
        self.assertLess(time.monotonic() - started, 7)
        self.assertIn('disconnected|', self.trace.read_text())
        self.assertFalse((self.runtime / 'lock').exists())

    def test_stop_interrupts_ppp_wait(self):
        self.start(TEST_PHASE='ppp')
        self.wait_for('ppp|')
        self.process.terminate()
        self.process.wait(timeout=7)
        trace = self.trace.read_text()
        self.assertIn('disconnected|', trace)
        self.assertIn('ip xfrm policy delete', trace)

    def test_retry_and_manual_stop(self):
        self.start(TEST_RECONNECT='1')
        self.wait_for('retrying|')
        self.process.terminate()
        self.process.wait(timeout=7)
        self.assertIn('disconnected|', self.trace.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
