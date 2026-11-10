#!/usr/bin/env python3
"""防火墙配置自愈：补齐缺失项、迁移旧接口、不覆盖用户修改、无改动不重载、不提交别人暂存的改动。"""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client/ensure-config'

# 按 libuci 的规则模拟用到的子命令，配置文件用 JSON 代替 UCI 文本：
# 读取时叠加所有暂存目录里同名配置的改动，默认暂存目录（/tmp/.uci）始终在其中；
# -t 只改变新改动写到哪里；commit 把叠加后的结果写回配置文件，只清空当前暂存目录里的改动。
FAKE_UCI = r'''#!/usr/bin/env python3
import json, os, sys
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
    conf = json.load(open(file))
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
        conf = load(cfg)
        # 模拟提交期间别人改了原配置文件
        race = os.environ.get('FAKE_UCI_RACE')
        if race:
            other = json.load(open(race))
            other['racer'] = {'.type': 'rule'}
            json.dump(other, open(race, 'w'), sort_keys=True)
        json.dump(conf, open(os.path.join(confdir, cfg), 'w'), sort_keys=True)
        own = os.path.join(savedir, cfg)
        if os.path.exists(own):
            open(own, 'w').close()
elif cmd == 'changes':
    for op in deltas(rest[0]):
        print(rest[0] + ': ' + json.dumps(op))
else:
    sys.exit(2)
'''


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
        for path in (self.bin, self.initd, self.sysnet, self.confdir, self.savedir, self.tempdir):
            path.mkdir()
        (self.bin / 'uci').write_text(FAKE_UCI)
        (self.bin / 'uci').chmod(0o755)
        self.trace = self.dir / 'trace'
        for name in ('network', 'firewall'):
            script = self.initd / name
            script.write_text(f'#!/bin/sh\necho "{name} $1" >> "{self.trace}"\n')
            script.chmod(0o755)
        self.write_state({'network': {}, 'firewall': {}})
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'TMPDIR': str(self.tempdir),
                    'FAKE_UCI_CONFDIR': str(self.confdir), 'FAKE_UCI_SAVEDIR': str(self.savedir),
                    'LP_CONFDIR': str(self.confdir), 'LP_CONF2DIR': str(self.dir / 'var-run-uci'),
                    'LP_INITD': str(self.initd), 'LP_SYSNET': str(self.sysnet), 'LP_UCI_FILE': str(self.dir / 'l2tpipsec')}

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, committed):
        for name, conf in committed.items():
            (self.confdir / name).write_text(json.dumps(conf, sort_keys=True))

    def config(self):
        return {path.name: json.loads(path.read_text()) for path in self.confdir.iterdir()}

    def stage(self, *args):
        """模拟其他操作用 uci set 暂存、尚未提交的改动。"""
        subprocess.run(['uci', *args], env=self.env, check=True)

    def staged(self, name):
        path = self.savedir / name
        return path.read_text().splitlines() if path.exists() else []

    def run_script(self, returncode=0, **env):
        result = subprocess.run(['sh', str(SCRIPT)], env={**self.env, **env}, capture_output=True, text=True)
        self.assertEqual(result.returncode, returncode, result.stderr)
        self.assertEqual(list(self.tempdir.iterdir()), [])
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

    def test_commits_only_own_changes_while_others_are_pending(self):
        self.write_state({'network': {'l2tpipsec': {'.type': 'interface', 'proto': 'none', 'device': 'l2tp-vpn'}},
                          'firewall': {'other': {'.type': 'rule', 'target': 'REJECT'}}})
        self.stage('set', 'firewall.other.target=ACCEPT')
        self.stage('set', 'network.lan=interface')
        self.assertEqual(self.run_script(), ['network reload', 'firewall reload'])
        config = self.config()
        self.assertEqual(config['firewall']['other']['target'], 'REJECT')
        self.assertEqual(config['firewall']['l2tpipsec']['.type'], 'zone')
        self.assertNotIn('l2tpipsec', config['network'])
        self.assertNotIn('lan', config['network'])
        # 别人的改动仍在暂存区，读取时照常叠加
        self.assertEqual(len(self.staged('firewall')), 1)
        self.assertEqual(len(self.staged('network')), 1)
        self.assertEqual(subprocess.run(['uci', 'get', 'firewall.other.target'], env=self.env,
                                        capture_output=True, text=True).stdout.strip(), 'ACCEPT')

    def test_does_not_overwrite_concurrent_commit(self):
        firewall = self.confdir / 'firewall'
        self.assertEqual(self.run_script(1, FAKE_UCI_RACE=str(firewall)), [])
        config = self.config()['firewall']
        self.assertIn('racer', config)
        self.assertNotIn('l2tpipsec', config)
        self.assertEqual(list(self.confdir.glob('.*')), [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
