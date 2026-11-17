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
WORKER = PACKAGE / 'usr/lib/l2tp-ipsec-client/worker'

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


def worker_function(name):
    """取 worker 里某个函数的源码，测试直接跑真实实现，避免和副本走偏。"""
    text = WORKER.read_text()
    start = text.index(f'\n{name}() {{')
    end = text.index('\n}\n', start) + 2
    return text[start + 1:end]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


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

    def shell(self, script, timeout=20):
        env = dict(os.environ)
        env['PATH'] = f"{self.bin}:{env['PATH']}"
        prelude = f'OUT={shlex.quote(str(self.output))}\n'
        return subprocess.run(
            ['sh', '-c', '. ' + shlex.quote(str(COMMON)) + '\n' + prelude + script],
            text=True, capture_output=True, env=env, timeout=timeout)

    def test_capture_survives_integer_only_sleep(self):
        result = self.shell(
            'lp_capture 3 "$OUT" printf \'l2tpipsec: #1, ESTABLISHED, IKEv1\\n'
            'l2tpipsec: #1, reqid 41717, INSTALLED, TRANSPORT\\n\'\n'
            'printf \'rc=%s\\n\' "$?"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=0', result.stdout, result.stderr)
        captured = self.output.read_text()
        self.assertIn('ESTABLISHED', captured)
        self.assertIn('INSTALLED', captured)

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

    def test_stop_kills_pending_watchdog(self):
        # 停止服务时 finish() 直接 exit，跳过 lp_capture 后面的回收。这里用 worker 里
        # 真实的 cleanup_attempt 收尾，看门狗必须一起结束，否则它到期会向旧 PID 发信号。
        run_dir = self.directory / 'run'
        run_dir.mkdir()
        script = (
            f'LP_DIR={shlex.quote(str(run_dir))}\n'
            'mkdir -p "$LP_DIR"\n'
            'printf \'%s\\n\' "$$" > "$LP_DIR/session"\n'
            f'{worker_function("cleanup_attempt")}\n'
            'finish() {\n'
            "\ttrap '' TERM INT\n"
            '\tprintf \'%s\\n\' "${command_watchdog:-none}" > "$LP_DIR/wd.pid"\n'
            '\tcleanup_attempt\n'
            '\texit 0\n'
            '}\n'
            'trap finish TERM INT\n'
            '( sleep 1; kill -TERM $$ ) &\n'
            'lp_capture 30 "$LP_DIR/captured" sleep 30\n'
        )
        result = self.shell(script)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        recorded = (run_dir / 'wd.pid').read_text().strip()
        self.assertRegex(recorded, r'^\d+$', '停止时没有记录看门狗，说明它没被纳入清理')
        watchdog = int(recorded)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and alive(watchdog):
            time.sleep(0.05)
        self.assertFalse(alive(watchdog), '停止后看门狗仍在运行')

    def test_worker_cleanup_stops_watchdog(self):
        body = worker_function('cleanup_attempt')
        self.assertIn('command_watchdog', body, 'cleanup_attempt 没有结束 lp_capture 的看门狗')

    def test_same_proc_decision_without_procfs(self):
        # 比对逻辑用假的启动时间来源验证，不依赖 /proc：
        # 值变了是别的进程，读不到是进程已经没了，都不该动手；
        # 一开始就取不到（没有 /proc）时按「还是它」处理，保证超时仍然生效。
        result = self.shell(
            'lp_proc_start() { printf \'%s\' "$FAKE"; }\n'
            'FAKE=100; lp_same_proc 1 200; printf \'changed=%s\\n\' "$?"\n'
            'FAKE=300; lp_same_proc 1 300; printf \'same=%s\\n\' "$?"\n'
            'FAKE=; lp_same_proc 1 300; printf \'gone=%s\\n\' "$?"\n'
            'FAKE=300; lp_same_proc 1 ""; printf \'noprocfs=%s\\n\' "$?"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('changed=1', result.stdout, result.stderr)
        self.assertIn('same=0', result.stdout, result.stderr)
        self.assertIn('gone=1', result.stdout, result.stderr)
        self.assertIn('noprocfs=0', result.stdout, result.stderr)

    @unittest.skipUnless(os.path.isdir('/proc'), '需要 /proc 才能比对进程启动时间')
    def test_same_proc_rejects_finished_process(self):
        # 看门狗到期前用它确认还行是不是当初那个进程：被 KILL 掉、或 PID 被复用时不能动手。
        result = self.shell(
            'sleep 5 & p=$!\n'
            'start=$(lp_proc_start "$p")\n'
            'printf \'start=%s\\n\' "${start:+ok}"\n'
            'lp_same_proc "$p" "$start"; printf \'live=%s\\n\' "$?"\n'
            'kill -KILL "$p"; wait "$p" 2>/dev/null\n'
            'lp_same_proc "$p" "$start"; printf \'gone=%s\\n\' "$?"\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('start=ok', result.stdout, result.stderr)
        self.assertIn('live=0', result.stdout, result.stderr)
        self.assertIn('gone=1', result.stdout, result.stderr)

    @unittest.skipUnless(os.path.isdir('/proc'), '需要 /proc 才能读进程状态')
    def test_proc_state_reads_real_state(self):
        result = self.shell('printf \'state=%s\\n\' "$(lp_proc_state $$)"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), r'^state=[RSD]$')

    def test_zombie_counts_as_dead(self):
        # busybox ash 不回收后台子进程，退出后一直是僵尸，kill -0 照样成功。
        # 不算作已结束的话，每停一个进程都要白等满上限，断开一次会拖到 procd 的 15 秒。
        # 这里用假的 /proc 读取验证判定本身，不依赖宿主是否回收子进程。
        result = self.shell(
            'lp_proc_state() { printf \'%s\' "$FAKE"; }\n'
            'sleep 30 & p=$!\n'
            'FAKE=Z; lp_alive "$p"; printf \'zombie=%s\\n\' "$?"\n'
            'FAKE=S; lp_alive "$p"; printf \'running=%s\\n\' "$?"\n'
            'FAKE=; lp_alive "$p"; printf \'unknown=%s\\n\' "$?"\n'
            'kill -9 "$p"; wait "$p" 2>/dev/null\n'
            'exit 0')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('zombie=1', result.stdout, '僵尸必须算作已结束')
        self.assertIn('running=0', result.stdout, result.stderr)
        self.assertIn('unknown=0', result.stdout, '取不到状态时按还活着处理，保证超时仍然生效')

    def test_stop_pid_honours_cleanup_budget(self):
        # 停止服务时 procd 只给 15 秒，预算用完必须立刻强杀，
        # 把时间留给撤销 xfrm 策略和删路由，那几步才是断开后的残渣来源。
        started = time.monotonic()
        result = self.shell(
            'READY="$OUT.ready"; export READY\n'
            'sh -c \'trap "" TERM; : > "$READY"; while :; do :; done\' & p=$!\n'
            'while [ ! -f "$READY" ]; do sleep 0.05; done\n'
            'LP_CLEANUP_LEFT=0\n'
            'lp_stop_pid "$p"\n'
            'printf \'rc=%s\\n\' "$?"\n'
            'wait "$p" 2>/dev/null; printf \'status=%s\\n\' "$?"\n'
            'exit 0')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('rc=0', result.stdout, result.stderr)
        # 137 = 被 SIGKILL 结束；进程忽略 TERM，只有我们的补刀能给出这个状态
        self.assertIn('status=137', result.stdout, '预算为 0 时应当直接 SIGKILL')
        self.assertLess(elapsed, 1.5, '预算为 0 时不该再等整秒')

    def test_stop_pid_waits_when_budget_allows(self):
        # 预算充足时仍然给进程体面退出的机会，只是上限仍是 2 秒
        started = time.monotonic()
        result = self.shell(
            'READY="$OUT.ready"; export READY\n'
            'sh -c \'trap "" TERM; : > "$READY"; while :; do :; done\' & p=$!\n'
            'while [ ! -f "$READY" ]; do sleep 0.05; done\n'
            'lp_stop_pid "$p"\n'
            'printf \'rc=%s\\n\' "$?"\n'
            'wait "$p" 2>/dev/null; printf \'status=%s\\n\' "$?"\n'
            'exit 0')
        elapsed = time.monotonic() - started
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('status=137', result.stdout, '忽略 TERM 的进程最终也要被 KILL')
        self.assertGreater(elapsed, 1.5, '正常情况下应当先等一等再强杀')
        self.assertLess(elapsed, 5, '单个进程最多等 2 秒')

    def test_worker_cleanup_has_time_budget(self):
        body = worker_function('cleanup_attempt')
        self.assertIn('LP_CLEANUP_LEFT=$LP_CLEANUP_BUDGET', body,
                      '清理开始时要重置总预算，否则会拖到 procd 强杀')

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
