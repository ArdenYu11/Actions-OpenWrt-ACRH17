#!/usr/bin/env python3
"""超时捕获的行为验证。

固件里的 busybox 有三处和常见开发环境不一样，都会让 lp_capture 误判：

1. 默认没编译小数延时（CONFIG_FLOAT_DURATION=n），`sleep 0.1` 直接报错退出，
   靠 tick 计数的等待会在几毫秒内跑完，把还在正常输出的命令当成超时杀掉。
2. ash 不回收后台子进程：命令退出后会一直是僵尸，`kill -0` 照样成功，
   用轮询判断结束会把正常结束的命令当成超时。
3. finish() 用 `trap '' TERM` 忽略停止信号，而「忽略」的处置会被子进程继承，
   只发 TERM 永远不会结束，等待一直挂着，清理执行不下去。

前两条会让 IPsec 明明建立成功却被判成协商失败，第三条会让断开时的清理卡住。
"""
import os
import pathlib
import re
import shlex
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE = ROOT / 'packages/l2tp-ipsec-client/files'
COMMON = PACKAGE / 'usr/lib/l2tp-ipsec-client/common.sh'

SCRIPTS = [
    'usr/lib/l2tp-ipsec-client/common.sh',
    'usr/lib/l2tp-ipsec-client/worker',
    'usr/lib/l2tp-ipsec-client/routing',
    'usr/lib/l2tp-ipsec-client/ensure-config',
    'usr/lib/l2tp-ipsec-client/ppp-hook',
    'usr/libexec/rpcd/l2tp-ipsec-client',
]


def function_body(name):
    """取 common.sh 里某个函数的源码，用于检查实现约束。"""
    text = COMMON.read_text()
    start = text.index(f'\n{name}() {{')
    end = text.index('\n}\n', start)
    return text[start:end]


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = pathlib.Path(self.tmp.name)
        self.output = self.directory / 'captured'
        # 按 busybox 默认配置模拟 sleep：只接受整数，小数直接失败退出
        self.bin = self.directory / 'bin'
        self.bin.mkdir()
        stub = self.bin / 'sleep'
        stub.write_text(
            '#!/bin/sh\n'
            'case "$1" in\n'
            "  *.*) echo \"sleep: invalid number '$1'\" >&2; exit 1 ;;\n"
            'esac\n'
            'exec /bin/sleep "$@"\n'
        )
        stub.chmod(0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def shell(self, script):
        env = dict(os.environ)
        env['PATH'] = f"{self.bin}:{env['PATH']}"
        prelude = f'OUT={shlex.quote(str(self.output))}\n'
        return subprocess.run(
            ['sh', '-c', '. ' + shlex.quote(str(COMMON)) + '\n' + prelude + script],
            text=True, capture_output=True, env=env)

    def test_capture_survives_integer_only_sleep(self):
        result = self.shell(
            'lp_capture 3 "$OUT" printf \'l2tpipsec: #1, ESTABLISHED, IKEv1\\n'
            'l2tpipsec: #1, reqid 41717, INSTALLED, TRANSPORT\\n\'\n'
            'rc=$?\n'
            'printf \'rc=%s\\n\' "$rc"\n'
            'cat "$OUT"', )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=0', result.stdout, result.stderr)
        self.assertIn('ESTABLISHED', result.stdout)
        self.assertIn('INSTALLED', result.stdout)

    def test_fast_command_is_not_reported_as_timeout(self):
        # 命令很快结束，就必须立刻拿到退出码。靠 kill -0 轮询的实现会一直看到
        # 僵尸进程，把这里判成超时——1.3.0 的 IPsec 误判正是这个形态。
        started = time.monotonic()
        result = self.shell('lp_capture 5 "$OUT" printf \'ok\\n\'; printf \'rc=%s\\n\' "$?"')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=0', result.stdout, result.stderr)
        self.assertLess(elapsed, 2, '命令已经结束，不该等到时限')

    def test_exit_status_is_passed_through(self):
        result = self.shell('lp_capture 3 "$OUT" sh -c \'exit 3\'; printf \'rc=%s\\n\' "$?"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=3', result.stdout, result.stderr)

    def test_capture_times_out_without_hanging(self):
        started = time.monotonic()
        result = self.shell('lp_capture 1 "$OUT" /bin/sleep 30; printf \'rc=%s\\n\' "$?"')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        # 超时码由 lp_capture 自己给，各环境一致；不能随 GNU/busybox 的 timeout 变成 143
        self.assertIn('rc=124', result.stdout, result.stderr)
        self.assertLess(elapsed, 6, '超时后仍有等待')

    def test_command_ignoring_term_is_still_killed(self):
        # 复现 finish() 的处境：子进程继承了「忽略 TERM」，只发 TERM 的等待会永远挂着。
        started = time.monotonic()
        result = self.shell(
            'lp_capture 1 "$OUT" sh -c \'trap "" TERM; exec sleep 30\'\n'
            'printf \'rc=%s\\n\' "$?"')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=124', result.stdout, result.stderr)
        self.assertLess(elapsed, 6, '忽略 TERM 的命令没有被强制结束')

    def test_scripts_do_not_use_fractional_sleep(self):
        pattern = re.compile(r'\bsleep\s+[0-9]+\.[0-9]+')
        for relative in SCRIPTS:
            with self.subTest(script=relative):
                text = (PACKAGE / relative).read_text()
                code = [line for line in text.splitlines()
                        if not line.lstrip().startswith('#')]
                self.assertNotRegex(
                    '\n'.join(code), pattern,
                    'busybox 没有小数延时，sleep N.N 在固件上会直接失败')

    def test_capture_does_not_poll_child_state(self):
        # busybox ash 不回收后台子进程，kill -0 对僵尸仍然成功；
        # 也不依赖 timeout 的实现，否则返回值会随 GNU/busybox 变化。
        body = function_body('lp_capture')
        self.assertNotIn('kill -0', body, '判断结束只能靠 wait，不能轮询 kill -0')
        self.assertNotIn('command -v timeout', body, '不要依赖 timeout 的实现差异')
        self.assertIn('KILL', body, '超时必须补一刀 SIGKILL，否则忽略 TERM 的命令会一直等')


if __name__ == '__main__':
    unittest.main(verbosity=2)
