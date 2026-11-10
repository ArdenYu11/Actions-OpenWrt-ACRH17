#!/usr/bin/env python3
"""防火墙配置自愈：补齐缺失项、迁移旧接口、不覆盖用户修改、无改动不重载、
不提交也不提前应用别人暂存的改动、不覆盖并发提交。"""
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client/ensure-config'

# 按 libuci 的规则模拟用到的子命令，配置文件用 JSON 代替 UCI 文本：
# - 读取时加共享锁，叠加所有暂存目录里同名配置的改动，默认暂存目录（/tmp/.uci）始终在其中；
# - -t 只改变新改动写到哪里；
# - commit 打开配置文件加排他锁，从这个打开的文件重新读取并叠加改动，在锁内清空当前暂存目录里的改动、
#   写好临时文件 .<配置名>.uci-XXXXXX，然后先关闭配置文件释放锁，再把临时文件改名替换（file.c 的 uci_file_commit）。
FAKE_UCI = r'''#!/usr/bin/env python3
import fcntl, json, os, sys, tempfile, time
confdir, default_save = os.environ['FAKE_UCI_CONFDIR'], os.environ['FAKE_UCI_SAVEDIR']
savedir, words, args = default_save, [], sys.argv[1:]
while args:
    arg = args.pop(0)
    if arg == '-c':
        confdir = args.pop(0)
    elif arg == '-t':
        savedir = args.pop(0)
    elif arg != '-q':
        words.append(arg)
paths = [default_save] + ([savedir] if savedir != default_save else [])
cmd, rest = words[0], words[1:]
def split(key):
    parts = key.split('.', 2)
    return parts + [None] * (3 - len(parts))
def deltas(cfg):
    ops = []
    for path in paths:
        file = os.path.join(path, cfg)
        if os.path.exists(file):
            ops += [json.loads(line) for line in open(file) if line.strip()]
    return ops
def apply(conf, op):
    kind, key, value = op
    _, sec, opt = split(key)
    if kind == 'delete':
        if opt is None:
            conf.pop(sec, None)
        else:
            conf.get(sec, {}).pop(opt, None)
    elif opt is None:
        conf.setdefault(sec, {})['.type'] = value
    elif kind == 'set':
        conf[sec][opt] = value
    elif kind == 'add_list':
        conf[sec].setdefault(opt, []).append(value)
    else:
        conf[sec][opt] = [v for v in conf[sec].get(opt, []) if v != value]
        if not conf[sec][opt]:
            del conf[sec][opt]
def load(cfg):
    file = os.path.join(confdir, cfg)
    if not os.path.exists(file):
        sys.exit(1)
    with open(file) as locked:
        fcntl.flock(locked, fcntl.LOCK_SH)
        conf = json.load(locked)
    for op in deltas(cfg):
        apply(conf, op)
    return conf
if cmd == 'get':
    cfg, sec, opt = split(rest[0])
    section = load(cfg).get(sec)
    if section is None or (opt is not None and opt not in section):
        sys.exit(1)
    value = section['.type'] if opt is None else section[opt]
    print(' '.join(value) if isinstance(value, list) else value)
elif cmd in ('set', 'add_list', 'del_list', 'delete'):
    key, value = (rest[0], None) if cmd == 'delete' else rest[0].split('=', 1)
    cfg = split(key)[0]
    apply(load(cfg), [cmd, key, value])
    os.makedirs(savedir, exist_ok=True)
    with open(os.path.join(savedir, cfg), 'a') as file:
        file.write(json.dumps([cmd, key, value]) + '\n')
elif cmd == 'commit':
    cfg = rest[0]
    if deltas(cfg):
        path = os.path.join(confdir, cfg)
        with open(path) as locked:
            fcntl.flock(locked, fcntl.LOCK_EX)
            conf = json.load(locked)
            for op in deltas(cfg):
                apply(conf, op)
            # 模拟生成副本期间别人改了原配置文件
            race = os.environ.get('FAKE_UCI_RACE')
            if race:
                other = json.load(open(race))
                other['racer'] = {'.type': 'rule'}
                json.dump(other, open(race, 'w'), sort_keys=True)
            own = os.path.join(savedir, cfg)
            if os.path.exists(own):
                open(own, 'w').close()
            fd, temp = tempfile.mkstemp(dir=confdir, prefix='.' + cfg + '.uci-')
            with os.fdopen(fd, 'w') as out:
                json.dump(conf, out, sort_keys=True)
        # 锁已随配置文件关闭释放，还没改名；测试可以让它停在这里
        pause = os.environ.get('FAKE_UCI_PAUSE_BEFORE_RENAME')
        if pause:
            open(os.path.join(pause, 'paused'), 'w').close()
            deadline = time.monotonic() + 5
            while not os.path.exists(os.path.join(pause, 'go')) and time.monotonic() < deadline:
                time.sleep(0.02)
        os.rename(temp, path)
        if pause:
            open(os.path.join(pause, 'done'), 'w').close()
elif cmd == 'changes':
    for op in deltas(rest[0]):
        print(rest[0] + ': ' + json.dumps(op))
else:
    sys.exit(2)
'''

# 与 busybox、util-linux 的「flock FD」相同：给继承来的描述符加锁，进程退出后锁仍归该描述符。
FAKE_FLOCK = r'''#!/usr/bin/env python3
import fcntl, sys
mode, fd = fcntl.LOCK_EX, None
for arg in sys.argv[1:]:
    if arg == '-s':
        mode = fcntl.LOCK_SH
    elif arg.isdigit():
        fd = int(arg)
fcntl.flock(fd, mode)
'''

# 挂载命名空间的替身：里面的进程看到的默认暂存目录换成一个空目录，外面不受影响。
FAKE_UNSHARE = '''#!/bin/sh
[ "$1" = -m ] || exit 2
shift
printf 'unshare\\n' >> "$FAKE_NS_TRACE"
[ "${FAKE_UNSHARE_FAIL:-0}" = 0 ] || exit 1
export FAKE_UCI_SAVEDIR="$FAKE_NS_SAVEDIR"
exec "$@"
'''

# 只接受脚本里那一种用法：在命名空间里把空 tmpfs 挂到默认暂存目录上
FAKE_MOUNT = '''#!/bin/sh
printf 'mount %s\\n' "$*" >> "$FAKE_NS_TRACE"
[ "$1 $2 $3 $4" = "-t tmpfs -o mode=0700" ] && [ "$6" = "$LP_UCI_SAVEDIR" ] && [ "$FAKE_UCI_SAVEDIR" = "$FAKE_NS_SAVEDIR" ]
'''

# 脚本最终核对原文件（对比副本原样与正式配置）之后，按 RACE_MODE 制造并发：
# - commit：另一个操作马上暂存并提交 firewall.other.target=DROP；
# - release：放行一个已放锁、停在改名之前的提交，等它改名完成；
# - stage：另一个操作马上暂存 firewall.other.target=ACCEPT，不提交。
# 新进程先关掉继承来的 9 号描述符，否则会一直占着脚本的锁。
RACE_CMP = '''#!/bin/sh
/usr/bin/cmp "$@"
rc=$?
if [ -n "${RACE_MODE:-}" ] && [ "$3" = "$RACE_AFTER_CMP" ] && mkdir "$RACE_DIR/started" 2>/dev/null; then
	case "$RACE_MODE" in
	commit)
		( exec 9<&-; uci set firewall.other.target=DROP && uci commit firewall; : > "$RACE_DIR/done" ) &
		# 没有互斥时这次提交马上完成；有互斥时它要等写回结束，这里最多等 1 秒
		i=0
		while [ ! -e "$RACE_DIR/done" ] && [ "$i" -lt 10 ]; do sleep 0.1; i=$((i + 1)); done
		;;
	release)
		: > "$RACE_DIR/go"
		i=0
		while [ ! -e "$RACE_DIR/done" ] && [ "$i" -lt 30 ]; do sleep 0.1; i=$((i + 1)); done
		;;
	stage)
		( exec 9<&-; uci set firewall.other.target=ACCEPT; : > "$RACE_DIR/staged" ) &
		;;
	esac
fi
exit "$rc"
'''

# 重新加载防火墙的替身：记下重新加载时按默认方式读到的 firewall.other.target，即 firewall4 会应用的值。
FAKE_FIREWALL = '''#!/bin/sh
echo "firewall $1" >> "$TEST_TRACE"
if [ "${RACE_MODE:-}" = stage ]; then
	i=0
	while [ ! -e "$RACE_DIR/staged" ] && [ "$i" -lt 50 ]; do sleep 0.1; i=$((i + 1)); done
fi
printf '%s\\n' "$(uci -q get firewall.other.target)" >> "$TEST_VIEW"
'''


def real_user_namespace():
    """当前环境能否以普通用户建立挂载命名空间（Linux，且未被 AppArmor 等限制）。"""
    tool = shutil.which('unshare')
    if not sys.platform.startswith('linux') or not tool:
        return None
    try:
        result = subprocess.run([tool, '-rm', 'sh', '-c', 'mount -t tmpfs none "$1"', 'sh', tempfile.gettempdir()],
                                capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return tool if result.returncode == 0 else None


REAL_UNSHARE = real_user_namespace()


class EnsureConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.bin = self.dir / 'bin'
        self.initd = self.dir / 'init.d'
        self.sysnet = self.dir / 'sys-class-net'
        self.confdir = self.dir / 'etc-config'
        self.savedir = self.dir / 'tmp-uci'
        self.tempdir = self.dir / 'tmp'
        self.race = self.dir / 'race'
        for path in (self.bin, self.initd, self.sysnet, self.confdir, self.savedir, self.tempdir, self.race,
                     self.dir / 'ns-uci'):
            path.mkdir()
        for name, source in (('uci', FAKE_UCI), ('flock', FAKE_FLOCK), ('cmp', RACE_CMP),
                             ('unshare', FAKE_UNSHARE), ('mount', FAKE_MOUNT)):
            (self.bin / name).write_text(source)
            (self.bin / name).chmod(0o755)
        self.trace = self.dir / 'trace'
        self.view = self.dir / 'view'
        self.ns_trace = self.dir / 'ns-trace'
        (self.initd / 'network').write_text('#!/bin/sh\necho "network $1" >> "$TEST_TRACE"\n')
        (self.initd / 'firewall').write_text(FAKE_FIREWALL)
        for name in ('network', 'firewall'):
            (self.initd / name).chmod(0o755)
        self.write_state({'network': {}, 'firewall': {}})
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'TMPDIR': str(self.tempdir),
                    'FAKE_UCI_CONFDIR': str(self.confdir), 'FAKE_UCI_SAVEDIR': str(self.savedir),
                    'FAKE_NS_SAVEDIR': str(self.dir / 'ns-uci'), 'FAKE_NS_TRACE': str(self.ns_trace),
                    'TEST_TRACE': str(self.trace), 'TEST_VIEW': str(self.view),
                    'RACE_DIR': str(self.race), 'RACE_AFTER_CMP': str(self.confdir / 'firewall'),
                    'LP_CONFDIR': str(self.confdir), 'LP_CONF2DIR': str(self.dir / 'var-run-uci'),
                    'LP_UCI_SAVEDIR': str(self.savedir),
                    'LP_INITD': str(self.initd), 'LP_SYSNET': str(self.sysnet), 'LP_UCI_FILE': str(self.dir / 'l2tpipsec')}

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, committed):
        for name, conf in committed.items():
            (self.confdir / name).write_text(json.dumps(conf, sort_keys=True))

    def config(self):
        return {path.name: json.loads(path.read_text()) for path in self.confdir.iterdir()}

    def stage(self, *args, **env):
        """模拟其他操作用 uci set 暂存、尚未提交的改动。"""
        subprocess.run(['uci', *args], env={**self.env, **env}, check=True)

    def staged(self, name):
        path = self.savedir / name
        return path.read_text().splitlines() if path.exists() else []

    def wait_for(self, path):
        deadline = time.monotonic() + 5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(path.exists(), path)

    def run_script(self, returncode=0, **env):
        result = subprocess.run(['sh', str(SCRIPT)], env={**self.env, **env}, capture_output=True, text=True)
        self.assertEqual(result.returncode, returncode, result.stdout + result.stderr)
        self.assertEqual(list(self.tempdir.iterdir()), [])
        self.output = result.stdout
        reloads = self.trace.read_text().splitlines() if self.trace.exists() else []
        if self.trace.exists():
            self.trace.unlink()
        return reloads

    def test_creates_missing_sections_once(self):
        self.assertEqual(self.run_script(), ['firewall reload'])
        firewall = self.config()['firewall']
        self.assertEqual(firewall['l2tpipsec']['.type'], 'zone')
        self.assertEqual(firewall['l2tpipsec']['device'], ['l2tp-vpn'])
        self.assertNotIn('network', firewall['l2tpipsec'])
        self.assertEqual(firewall['l2tpipsec']['masq'], '1')
        self.assertEqual(firewall['l2tpipsec_lan']['dest'], 'l2tpipsec')
        self.assertEqual(firewall['l2tpipsec_input']['chain'], 'input')
        self.assertEqual(firewall['l2tpipsec_snat']['chain'], 'srcnat')
        self.assertEqual(firewall['l2tpipsec_dns']['dest_port'], '1053')
        # 防火墙在独立的挂载命名空间里重新加载，空 tmpfs 挂在默认暂存目录上
        self.assertEqual(self.ns_trace.read_text().splitlines(),
                         ['unshare', f'mount -t tmpfs -o mode=0700 l2tpipsec {self.savedir}'])
        self.assertEqual(self.run_script(), [])

    def test_migrates_legacy_netifd_interface(self):
        self.write_state({
            'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'none', 'device': 'l2tp-vpn'}},
            'firewall': {'l2tpipsec': {'.type': 'zone', 'name': 'l2tpipsec', 'network': ['l2tpipsec'], 'masq': '0'}},
        })
        self.assertEqual(self.run_script(), ['network reload', 'firewall reload'])
        config = self.config()
        self.assertNotIn('l2tpipsec', config['network'])
        zone = config['firewall']['l2tpipsec']
        self.assertEqual(zone['device'], ['l2tp-vpn'])
        self.assertNotIn('network', zone)
        # 已有区域的策略选项不覆盖
        self.assertEqual(zone['masq'], '0')

    def test_keeps_legacy_interface_while_vpn_is_up(self):
        (self.sysnet / 'l2tp-vpn').mkdir()
        self.write_state({'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'none', 'device': 'l2tp-vpn'}},
                          'firewall': {}})
        self.assertEqual(self.run_script(), ['firewall reload'])
        self.assertIn('l2tpipsec', self.config()['network'])

    def test_leaves_unrelated_network_section(self):
        self.write_state({'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'static', 'device': 'eth9'}},
                          'firewall': {}})
        self.run_script()
        self.assertIn('l2tpipsec', self.config()['network'])

    def test_complete_config_leaves_pending_changes_of_others_alone(self):
        self.write_state({'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.run_script()
        self.stage('set', 'firewall.other.target=ACCEPT')
        self.stage('set', 'network.lan=interface')
        self.assertEqual(self.run_script(), [])
        self.assertEqual(self.config()['firewall']['other']['target'], 'REJECT')
        self.assertNotIn('lan', self.config()['network'])
        self.assertEqual(len(self.staged('firewall')), 1)
        self.assertEqual(len(self.staged('network')), 1)

    def test_neither_commits_nor_applies_pending_changes_of_others(self):
        # 插件配置缺失，同时有别人暂存的改动：本次不写回、不重载
        self.write_state({'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'none', 'device': 'l2tp-vpn'}},
                          'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.stage('set', 'firewall.other.target=ACCEPT')
        self.stage('set', 'network.lan=interface')
        self.assertEqual(self.run_script(1), [])
        self.assertIn('uci changes firewall', self.output)
        self.assertIn('uci changes network', self.output)
        config = self.config()
        self.assertEqual(config['firewall'], {'other': {'.type': 'rule', 'target': 'REJECT'}})
        self.assertIn('l2tpipsec', config['network'])
        # 别人的改动仍在暂存区，由他们自己提交或放弃
        self.assertEqual(len(self.staged('firewall')), 1)
        self.assertEqual(len(self.staged('network')), 1)
        # 放弃之后，下次连接补齐
        for name in ('firewall', 'network'):
            (self.savedir / name).unlink()
        self.assertEqual(self.run_script(), ['network reload', 'firewall reload'])
        self.assertEqual(self.config()['firewall']['l2tpipsec']['.type'], 'zone')
        self.assertEqual(self.view.read_text().splitlines(), ['REJECT'])

    def test_pending_changes_only_hold_back_their_own_config(self):
        self.write_state({'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'none', 'device': 'l2tp-vpn'}},
                          'firewall': {}})
        self.stage('set', 'network.lan=interface')
        self.assertEqual(self.run_script(1), ['firewall reload'])
        self.assertIn('uci changes network', self.output)
        self.assertNotIn('uci changes firewall', self.output)
        config = self.config()
        self.assertEqual(config['firewall']['l2tpipsec']['.type'], 'zone')
        self.assertIn('l2tpipsec', config['network'])

    def test_reload_ignores_changes_staged_after_check(self):
        # 检查暂存区之后、重新加载之前，另一个会话暂存了 ACCEPT
        self.write_state({'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.assertEqual(self.run_script(RACE_MODE='stage'), ['firewall reload'])
        self.assertTrue((self.race / 'staged').exists())
        # 重新加载读到的是已提交的 REJECT；ACCEPT 仍在暂存区，磁盘上也没提交
        self.assertEqual(self.view.read_text().splitlines(), ['REJECT'])
        self.assertEqual(self.config()['firewall']['other']['target'], 'REJECT')
        self.assertEqual(len(self.staged('firewall')), 1)

    def test_failed_isolated_reload_is_reported(self):
        self.assertEqual(self.run_script(1, FAKE_UNSHARE_FAIL='1'), [])
        self.assertIn('重新加载失败', self.output)
        self.assertEqual(self.config()['firewall']['l2tpipsec']['.type'], 'zone')

    def test_does_not_overwrite_commit_made_while_preparing(self):
        firewall = self.confdir / 'firewall'
        self.assertEqual(self.run_script(1, FAKE_UCI_RACE=str(firewall)), [])
        self.assertIn('firewall 配置在检查期间被其他操作修改', self.output)
        config = self.config()['firewall']
        self.assertIn('racer', config)
        self.assertNotIn('l2tpipsec', config)
        self.assertEqual(list(self.confdir.glob('.*')), [])

    def test_commit_after_final_check_waits_and_is_kept(self):
        self.write_state({'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.assertEqual(self.run_script(RACE_MODE='commit'), ['firewall reload'])
        self.assertTrue((self.race / 'started').exists())
        self.wait_for(self.race / 'done')
        # 另一个操作读取和提交都要等写回结束，基于写回后的文件提交，两边的改动都在
        config = self.config()['firewall']
        self.assertEqual(config['other']['target'], 'DROP')
        self.assertEqual(config['l2tpipsec']['.type'], 'zone')
        self.assertEqual(self.staged('firewall'), [])
        self.assertEqual(self.run_script(), [])
        self.assertEqual(list(self.confdir.glob('.*')), [])

    def test_commit_released_lock_but_not_renamed_is_kept(self):
        # 另一个提交已在锁内写好 DROP 的临时文件并放锁，还停在改名之前；
        # 脚本拿到锁后，即使在最终核对之后放它改名，也不能用旧副本覆盖
        self.write_state({'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.stage('set', 'firewall.other.target=DROP')
        committer = subprocess.Popen(['uci', 'commit', 'firewall'],
                                     env={**self.env, 'FAKE_UCI_PAUSE_BEFORE_RENAME': str(self.race)})
        try:
            self.wait_for(self.race / 'paused')
            self.assertEqual(self.run_script(1, RACE_MODE='release'), [])
            self.assertIn('正在提交', self.output)
        finally:
            (self.race / 'go').touch()
            committer.wait(timeout=5)
        self.assertEqual(self.config()['firewall']['other']['target'], 'DROP')
        # 改名完成后再检查，补齐本插件配置，DROP 保留
        self.assertEqual(self.run_script(), ['firewall reload'])
        config = self.config()['firewall']
        self.assertEqual(config['other']['target'], 'DROP')
        self.assertEqual(config['l2tpipsec']['.type'], 'zone')

    def test_stale_temp_file_from_crashed_commit_is_ignored(self):
        stale = self.confdir / '.firewall.uci-abc123'
        stale.write_text('{}')
        old = time.time() - 300
        os.utime(stale, (old, old))
        self.assertEqual(self.run_script(), ['firewall reload'])
        self.assertEqual(self.config()['firewall']['l2tpipsec']['.type'], 'zone')
        stale.unlink()

    @unittest.skipUnless(REAL_UNSHARE, '需要 Linux 且允许普通用户建立挂载命名空间')
    def test_real_mount_namespace_hides_staged_changes(self):
        # 用真实的 unshare 和 mount：普通用户加 -r 映射成命名空间里的 root
        (self.bin / 'mount').unlink()
        (self.bin / 'unshare').write_text(f'#!/bin/sh\nexec {REAL_UNSHARE} -r "$@"\n')
        self.write_state({'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.assertEqual(self.run_script(RACE_MODE='stage'), ['firewall reload'])
        self.assertEqual(self.view.read_text().splitlines(), ['REJECT'])
        # 命名空间里的挂载不影响外面：暂存的 ACCEPT 仍在原处，按默认方式读取仍能看到
        self.assertEqual(len(self.staged('firewall')), 1)
        self.assertEqual(subprocess.run(['uci', 'get', 'firewall.other.target'], env=self.env,
                                        capture_output=True, text=True).stdout.strip(), 'ACCEPT')


if __name__ == '__main__':
    unittest.main(verbosity=2)
