#!/usr/bin/env python3
"""防火墙配置自愈：补齐缺失项、迁移旧接口、不覆盖用户修改、无改动不重载。"""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client/ensure-config'

# 只实现 ensure-config 用到的 uci 子命令：改动先暂存，commit 后生效，changes 列出未提交的配置。
FAKE_UCI = r'''#!/usr/bin/env python3
import json, os, sys
path = os.environ['FAKE_UCI_STATE']
state = json.load(open(path))
args = [a for a in sys.argv[1:] if a != '-q']
cmd, rest = args[0], args[1:]
committed, staged = state['committed'], state['staged']
def current(cfg):
    return staged.get(cfg, committed.get(cfg, {}))
def stage(cfg):
    staged.setdefault(cfg, json.loads(json.dumps(committed.get(cfg, {}))))
    return staged[cfg]
def split(key):
    parts = key.split('.', 2)
    return parts + [None] * (3 - len(parts))
def save():
    json.dump(state, open(path, 'w'))
if cmd == 'get':
    cfg, sec, opt = split(rest[0])
    section = current(cfg).get(sec)
    if section is None:
        sys.exit(1)
    if opt is None:
        print(section['.type']); sys.exit(0)
    if opt not in section:
        sys.exit(1)
    value = section[opt]
    print(' '.join(value) if isinstance(value, list) else value)
elif cmd in ('set', 'add_list', 'del_list'):
    key, value = rest[0].split('=', 1)
    cfg, sec, opt = split(key)
    conf = stage(cfg)
    if opt is None:
        conf.setdefault(sec, {})['.type'] = value
    elif cmd == 'set':
        conf[sec][opt] = value
    elif cmd == 'add_list':
        conf[sec].setdefault(opt, []).append(value)
    else:
        conf[sec][opt] = [v for v in conf[sec].get(opt, []) if v != value]
    save()
elif cmd == 'delete':
    cfg, sec, opt = split(rest[0])
    conf = stage(cfg)
    if opt is None:
        conf.pop(sec, None)
    else:
        conf.get(sec, {}).pop(opt, None)
    save()
elif cmd == 'changes':
    cfg = rest[0]
    if cfg in staged and staged[cfg] != committed.get(cfg, {}):
        print(cfg + ': changed')
elif cmd == 'commit':
    cfg = rest[0]
    if cfg in staged:
        committed[cfg] = staged.pop(cfg)
    save()
elif cmd == 'show':
    cfg = rest[0]
    for sec, opts in current(cfg).items():
        print(f"{cfg}.{sec}={opts['.type']}")
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
        for path in (self.bin, self.initd, self.sysnet):
            path.mkdir()
        (self.bin / 'uci').write_text(FAKE_UCI)
        (self.bin / 'uci').chmod(0o755)
        self.trace = self.dir / 'trace'
        for name in ('network', 'firewall'):
            script = self.initd / name
            script.write_text(f'#!/bin/sh\necho "{name} $1" >> "{self.trace}"\n')
            script.chmod(0o755)
        self.state = self.dir / 'uci.json'
        self.write_state({'network': {}, 'firewall': {}})
        self.env = {**os.environ, 'PATH': f'{self.bin}:{os.environ["PATH"]}', 'FAKE_UCI_STATE': str(self.state),
                    'LP_INITD': str(self.initd), 'LP_SYSNET': str(self.sysnet), 'LP_UCI_FILE': str(self.dir / 'l2tpipsec')}

    def tearDown(self):
        self.tmp.cleanup()

    def write_state(self, committed):
        self.state.write_text(json.dumps({'committed': committed, 'staged': {}}))

    def config(self):
        return json.loads(self.state.read_text())['committed']

    def run_script(self):
        result = subprocess.run(['sh', str(SCRIPT)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
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
        self.assertEqual(zone['network'], [])
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
