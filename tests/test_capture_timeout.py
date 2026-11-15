#!/usr/bin/env python3
"""超时捕获与小延时等待的行为验证。

固件里的 busybox 默认没有编译小数延时（CONFIG_FLOAT_DURATION=n），
`sleep 0.1` 会直接报错退出。用 tick 计数的等待循环会在几毫秒内跑完，
把还在正常输出的命令当成超时杀掉——真机上表现为 IPsec 明明建立成功，
却被判定为协商失败。
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

    def test_capture_times_out_without_hanging(self):
        started = time.monotonic()
        result = self.shell('lp_capture 1 "$OUT" /bin/sleep 30; printf \'rc=%s\\n\' "$?"')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=124', result.stdout)
        self.assertLess(elapsed, 6, '超时后仍有等待')

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
