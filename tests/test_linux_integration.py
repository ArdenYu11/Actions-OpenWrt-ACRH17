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
 mtu=1400; lcp_interval=30; lcp_failure=5; retry_interval=${TEST_RETRY_INTERVAL:-10}; retry_max_attempts=${TEST_MAX_RETRIES:-0}
 probe_ip=; routes=; routing_mode=rules; reconnect=${TEST_RECONNECT:-0}
}
lp_state() { printf '%s|%s\\n' "$1" "$2" >> "$TEST_TRACE"; }
lp_has_ipsec() { [ "${TEST_PHASE:-}" = ppp ]; }
lp_swan() { return 0; }
''')
        worker = (self.lib / 'worker').read_text().replace(
            '. /usr/lib/l2tp-ipsec-client/common.sh', f'. {common}')
        worker = worker.replace('/usr/lib/ipsec/charon', str(self.bin / 'charon'))
        (self.lib / 'worker').write_text(worker)
        self.xl2tpd_run = self.directory / 'xl2tpd-run'
        self.env = {**os.environ, 'LP_DIR': str(self.runtime), 'LP_LIB': str(self.lib),
                    'LP_XL2TPD_RUN': str(self.xl2tpd_run),
                    'TEST_TRACE': str(self.trace), 'PATH': str(self.bin) + ':' + os.environ['PATH']}
        mocks = {
            'resolveip': '[ "${TEST_RESOLVE_FAIL:-0}" = 0 ] && echo 192.0.2.20',
            'pidof': '[ "${TEST_CONFLICT:-0}" = 1 ] && [ "$1" = xl2tpd ] && echo 4242',
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
            # 真实的 xl2tpd-control 把结果管道写死在 /var/run/xl2tpd，目录不在就直接失败
            'xl2tpd-control': '''if [ "${TEST_L2TP_FAIL:-0}" = 1 ] || [ ! -d "$LP_XL2TPD_RUN" ]; then
 echo "error: unable to open $LP_XL2TPD_RUN/xl2tpd-control-$$.out for reading." >&2
 exit 254
fi
printf 'xl2tpd-control-ok\\n' >> "$TEST_TRACE"''',
        }
        for name, source in mocks.items():
            path = self.bin / name
            path.write_text('#!/bin/sh\n' + source + '\n')
            path.chmod(0o755)
        (self.lib / 'ppp-hook').write_text('#!/bin/sh\nexit 0\n')
        for name in ('routing', 'ensure-config'):
            (self.lib / name).write_text(f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >> "$TEST_TRACE"\nexit 0\n')
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

    def events(self):
        path = self.runtime / 'events.log'
        return path.read_text() if path.exists() else ''

    def test_existing_service_conflict_does_not_change_routes(self):
        self.start(TEST_CONFLICT='1')
        self.process.wait(timeout=5)
        trace = self.trace.read_text()
        self.assertIn('conflict|', trace)
        self.assertIn('xl2tpd（PID 4242）', trace)
        self.assertIn('/etc/init.d/xl2tpd stop', trace)
        self.assertNotIn('ip xfrm policy update', trace)
        self.assertFalse((self.runtime / 'lock').exists())

    def test_failure_cleans_owned_routes_and_credentials(self):
        self.start()
        self.process.wait(timeout=8)
        trace = self.trace.read_text()
        self.assertIn('error|IPsec 协商失败', trace)
        self.assertIn('ip xfrm policy update', trace)
        self.assertIn('ip xfrm policy delete', trace)
        self.assertIn('ip -4 route del 192.0.2.20/32 metric 41717', trace)
        self.assertFalse((self.runtime / 'swanctl.conf').exists())
        self.assertFalse((self.runtime / 'ppp.options').exists())
        self.assertIn('自动重连已关闭', self.events())

    def test_config_check_and_leftover_cleanup_run_before_connect(self):
        self.runtime.mkdir()
        (self.runtime / 'ppp.up').write_text('')
        (self.runtime / 'server-ip').write_text('198.51.100.7\n')
        self.start(TEST_PHASE='ipsec')
        self.wait_for('ipsec-wait')
        trace = self.trace.read_text()
        self.assertIn('routing purge', trace)
        self.assertIn('ensure-config', trace)
        self.assertIn('ip xfrm policy delete dir out src 0.0.0.0/0 dst 198.51.100.7/32', trace)
        self.assertIn('ip -4 route del 198.51.100.7/32 metric 41717', trace)
        self.assertLess(trace.index('routing purge'), trace.index('resolving|'))
        self.assertFalse((self.runtime / 'ppp.up').exists())

    def test_config_check_reason_is_logged(self):
        (self.lib / 'ensure-config').write_text('#!/bin/sh\necho "防火墙配置有尚未提交的其他改动"\n'
                                                'echo "第二行原因"\necho "重载输出" >&2\nexit 1\n')
        self.start(TEST_RESOLVE_FAIL='1')
        self.process.wait(timeout=8)
        events = self.events()
        self.assertIn('防火墙配置有尚未提交的其他改动', events)
        self.assertIn('第二行原因', events)
        self.assertNotIn('重载输出', events)

    @unittest.skipUnless(os.path.exists('/proc/self/comm'), '需要 Linux /proc 核对进程名')
    def test_orphaned_process_from_crashed_session_is_stopped(self):
        self.runtime.mkdir()
        orphan = subprocess.Popen([str(self.bin / 'charon')], env={**self.env})
        try:
            deadline = time.monotonic() + 3
            while not (self.runtime / 'charon.vici').exists() and time.monotonic() < deadline:
                time.sleep(.05)
            (self.runtime / 'charon.pid').write_text(f'{orphan.pid}\n')
            self.start(TEST_PHASE='ipsec')
            self.wait_for('ipsec-wait')
            orphan.wait(timeout=5)
        finally:
            if orphan.poll() is None:
                orphan.kill()
                orphan.wait()

    def test_l2tp_dial_creates_result_pipe_directory(self):
        self.start(TEST_PHASE='ppp')
        self.wait_for('xl2tpd-control-ok')
        self.assertTrue(self.xl2tpd_run.is_dir())
        self.assertIn('ppp|', self.trace.read_text())
        self.assertIn('手机上确认登录', self.trace.read_text())

    def test_l2tp_dial_failure_is_logged(self):
        self.start(TEST_PHASE='ppp', TEST_L2TP_FAIL='1')
        self.process.wait(timeout=8)
        self.assertIn('error|L2TP 拨号失败', self.trace.read_text())
        events = self.events()
        self.assertIn('unable to open', events)
        self.assertIn('自动重连已关闭', events)

    def test_superseded_worker_leaves_new_session_alone(self):
        self.start(TEST_PHASE='ipsec')
        self.wait_for('ipsec-wait')
        (self.runtime / 'session').write_text('999999\n')
        self.process.terminate()
        self.process.wait(timeout=7)
        self.assertNotIn('disconnected|', self.trace.read_text())
        self.assertTrue((self.runtime / 'lock').exists())
        self.assertNotIn('ip xfrm policy delete dir out src 0.0.0.0/0 dst 192.0.2.20/32', self.trace.read_text())

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

    def test_reconnect_limit_stops_after_configured_retries(self):
        self.start(TEST_RECONNECT='1', TEST_MAX_RETRIES='3', TEST_RETRY_INTERVAL='1', TEST_RESOLVE_FAIL='1')
        self.process.wait(timeout=7)
        trace = self.trace.read_text()
        self.assertEqual(trace.count('resolving|'), 4)
        self.assertEqual(trace.count('retrying|'), 3)
        self.assertIn('已达到最大重连次数（3 次）', trace)
        self.assertFalse((self.runtime / 'lock').exists())

    def test_retry_and_manual_stop(self):
        self.start(TEST_RECONNECT='1')
        self.wait_for('retrying|')
        self.process.terminate()
        self.process.wait(timeout=7)
        self.assertIn('disconnected|', self.trace.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
