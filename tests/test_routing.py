#!/usr/bin/env python3
"""路由两模式、DNS 依赖及冲突清理测试，命令限定在测试替身内。"""
import os
import pathlib
import shlex
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client'


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.bin = self.dir / 'bin'
        self.bin.mkdir()
        self.trace = self.dir / 'trace'
        self.env = {**os.environ, 'LP_DIR': str(self.dir), 'LP_LIB': str(self.bin),
                    'TRACE': str(self.trace), 'PATH': str(self.bin) + ':' + os.environ['PATH']}
        self.script = self.dir / 'routing'
        source = (LIB / 'routing').read_text().replace('. /usr/lib/l2tp-ipsec-client/common.sh', '. ' + shlex.quote(str(LIB / 'common.sh')))
        source = source.replace('. /lib/functions/network.sh', 'network_get_device() { device=br-lan; }')
        self.script.write_text(source)
        mocks = {
            'ip': '''printf 'ip %s\\n' "$*" >> "$TRACE"
case "$*" in
*"route show table 41717 exact"*|*"route show table 41717 default"*) [ "${MISSING:-0}" = 1 ] || echo 'x dev l2tp-vpn' ;;
*"route show table 41717"*) [ "${CONFLICT:-0}" = 1 ] && echo 'default dev other'; [ -z "${TABLE:-}" ] || printf '%s\\n' "$TABLE" ;;
*"rule show"*) [ "${RULES:-0}" = 1 ] && printf '10104:\\tfrom all lookup 41717\\n' ;;
*"rule del"*) exit 1 ;;
*"route show table main"*) echo '192.168.1.0/24 dev br-lan proto kernel scope link' ;;
esac
exit 0''',
            'nft': 'printf "nft %s\\n" "$*" >> "$TRACE"\n[ "$1" != list ]',
            'domain-dns': '''printf 'dns %s\\n' "$*" >> "$TRACE"
while [ "$#" -gt 0 ]; do
 if [ "$1" = --ready ]; then touch "$2"; fi
 shift
done
exit 0'''
        }
        for name, content in mocks.items():
            file = self.bin / name
            file.write_text('#!/bin/sh\n' + content + '\n')
            file.chmod(0o755)
        for name, content in [('routing-mode', 'rules'), ('configured-dns', ''), ('server-ip', '192.0.2.20'),
                              ('routes', '10.20.0.0/16\n10.30.0.1/32'), ('domain-rules', '')]:
            (self.dir / name).write_text(content + '\n' if content else '')

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, action, **env):
        return subprocess.run(['sh', str(self.script), action], env={**self.env, **env}, capture_output=True, text=True)

    def test_subnets_and_policy_table(self):
        result = self.run_script('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace.read_text()
        self.assertIn('rule add priority 10100 to 192.0.2.20/32 lookup main', trace)
        self.assertIn('rule add priority 10103 to 192.168.1.0/24 lookup main', trace)
        self.assertIn('route replace 10.20.0.0/16 dev l2tp-vpn table 41717', trace)
        self.assertNotIn('route replace default', trace)
        self.assertNotIn('dns --', trace)
        self.trace.write_text('')
        self.assertEqual(self.run_script('down').returncode, 0)
        trace = self.trace.read_text()
        self.assertIn('route flush table 41717', trace)
        # 按记录逐条删除自己加的规则
        for rule in ('priority 10100 to 192.0.2.20/32 lookup main', 'priority 10102 fwmark 41717 lookup main',
                     'priority 10103 to 192.168.1.0/24 lookup main', 'priority 10104 lookup 41717'):
            self.assertIn(f'rule del {rule}\n', trace)
        self.assertFalse((self.dir / 'routing-rules').exists())

    def test_domain_and_subnet_rules_together(self):
        (self.dir / 'domain-rules').write_text('prefix api.\n')
        result = self.run_script('up', DNS1='10.20.0.53')
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace.read_text()
        self.assertIn('route replace 10.20.0.0/16', trace)
        self.assertIn('rule add priority 10101 to 10.20.0.53/32 lookup 41717', trace)
        self.assertIn('--vpn-dns 10.20.0.53 --local-dns 127.0.0.1 --mode rules', trace)
        nft = (self.dir / 'dns.nft').read_text()
        self.assertIn('fib daddr type local', nft)
        self.assertIn('ip6 daddr ::1', nft)
        self.assertIn('iifname { "br-lan" }', nft)
        self.assertNotIn('chain ipv6_forward', nft)

    def test_full_mode_and_configured_dns_override(self):
        (self.dir / 'routing-mode').write_text('full\n')
        (self.dir / 'configured-dns').write_text('10.30.0.53\n')
        result = self.run_script('up', DNS1='10.20.0.53')
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace.read_text()
        self.assertIn('route replace default dev l2tp-vpn table 41717', trace)
        self.assertNotIn('route replace 10.20.0.0/16', trace)
        self.assertIn('--vpn-dns 10.30.0.53', trace)
        self.assertIn('suppress_prefixlength 0', trace)
        self.assertIn('chain ipv6_forward', (self.dir / 'dns.nft').read_text())

    def test_peer_dns_file_used_without_pppd_env(self):
        (self.dir / 'domain-rules').write_text('prefix api.\n')
        (self.dir / 'peer-dns').write_text('10.20.0.53\n')
        result = self.run_script('up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--vpn-dns 10.20.0.53', self.trace.read_text())

    def test_purge_keeps_rules_and_table_of_other_services(self):
        # 其他服务占用了同一优先级和表，本插件没有归属标记和规则记录
        result = self.run_script('purge', RULES='1', CONFLICT='1')
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace.read_text()
        self.assertNotIn('rule del', trace)
        self.assertNotIn('route flush', trace)
        self.assertIn('nft delete table inet l2tpipsec_dns', trace)
        # 随后的连接拒绝启动并说明原因，不覆盖
        self.assertNotEqual(self.run_script('up', RULES='1').returncode, 0)
        self.assertIn('已被其他服务占用', (self.dir / 'route.error').read_text())
        self.assertNotIn('rule add', self.trace.read_text())

    def test_purge_removes_recorded_leftovers(self):
        (self.dir / 'domain-rules').write_text('prefix api.\n')
        self.assertEqual(self.run_script('up', DNS1='10.20.0.53').returncode, 0)
        # 工作进程异常退出，运行目录里的标记和记录还在
        self.trace.write_text('')
        self.assertEqual(self.run_script('purge').returncode, 0)
        trace = self.trace.read_text()
        self.assertIn('rule del priority 10101 to 10.20.0.53/32 lookup 41717\n', trace)
        self.assertIn('rule del priority 10104 lookup 41717\n', trace)
        self.assertIn('route flush table 41717', trace)
        for name in ('routing-owned', 'routing-rules', 'active-dns', 'learned-routes'):
            self.assertFalse((self.dir / name).exists(), name)

    def test_check_detects_missing_learned_route(self):
        (self.dir / 'routing-owned').write_text('')
        (self.dir / 'learned-routes').write_text('10.20.1.2\n10.20.1.3\n')
        both = '10.20.0.0/16 dev l2tp-vpn proto static metric 41717\n' \
               '10.20.1.2 dev l2tp-vpn proto static metric 41718\n10.20.1.3/32 dev l2tp-vpn proto static metric 41718'
        self.assertEqual(self.run_script('check', RULES='1', TABLE=both).returncode, 0)
        one = '10.20.1.2 dev l2tp-vpn proto static metric 41718'
        self.assertNotEqual(self.run_script('check', RULES='1', TABLE=one).returncode, 0)
        self.assertNotEqual(self.run_script('check', RULES='1').returncode, 0)
        # 只有前缀相同的地址不能算作已安装
        prefix_only = '10.20.1.2 dev l2tp-vpn\n10.20.1.30 dev l2tp-vpn\n10.20.1.3.0 dev l2tp-vpn'
        self.assertNotEqual(self.run_script('check', RULES='1', TABLE=prefix_only).returncode, 0)

    def test_repair_keeps_dns_process_and_learned_routes(self):
        (self.dir / 'domain-rules').write_text('prefix api.\n')
        self.assertEqual(self.run_script('up', DNS1='10.20.0.53').returncode, 0)
        (self.dir / 'learned-routes').write_text('10.20.1.2\n10.20.1.3\n')
        self.trace.write_text('')
        table = '10.20.1.2 dev l2tp-vpn\n10.20.1.3 dev l2tp-vpn'
        result = self.run_script('repair', RULES='1', TABLE=table)
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = self.trace.read_text()
        self.assertNotIn('dns --', trace)
        self.assertNotIn('route flush', trace)
        self.assertIn('rule del priority 10104 lookup 41717\n', trace)
        self.assertIn('rule add priority 10104 lookup 41717\n', trace)
        self.assertIn('rule add priority 10101 to 10.20.0.53/32 lookup 41717\n', trace)
        self.assertIn('route replace 10.20.0.0/16 dev l2tp-vpn table 41717', trace)
        self.assertIn('route replace 10.20.0.53/32 dev l2tp-vpn table 41717', trace)
        for address in ('10.20.1.2', '10.20.1.3'):
            self.assertIn(f'route replace {address} dev l2tp-vpn table 41717 proto static metric 41718', trace)
        # nft 表被清掉时按保存的规则补回
        self.assertIn(f'nft -f {self.dir}/dns.nft', trace)
        self.assertTrue((self.dir / 'learned-routes').exists())
        # 补回后动态路由仍缺失，检查失败
        self.assertNotEqual(self.run_script('repair', RULES='1').returncode, 0)

    def test_repair_requires_ownership(self):
        self.assertNotEqual(self.run_script('repair', RULES='1').returncode, 0)
        self.assertNotIn('rule', self.trace.read_text() if self.trace.exists() else '')

    def test_check_detects_missing_routes(self):
        self.assertNotEqual(self.run_script('check', RULES='1').returncode, 0)
        (self.dir / 'routing-owned').write_text('')
        self.assertEqual(self.run_script('check', RULES='1').returncode, 0)
        self.assertNotEqual(self.run_script('check', RULES='0').returncode, 0)
        self.assertNotEqual(self.run_script('check', RULES='1', MISSING='1').returncode, 0)
        (self.dir / 'routing-mode').write_text('full\n')
        self.assertEqual(self.run_script('check', RULES='1').returncode, 0)
        self.assertIn('route show table 41717 default', self.trace.read_text())
        (self.dir / 'active-dns').write_text('10.20.0.53\n')
        self.assertEqual(self.run_script('check', RULES='1').returncode, 0)
        self.assertIn('route show table 41717 exact 10.20.0.53/32', self.trace.read_text())

    def test_missing_dns_and_conflict_cleanup(self):
        (self.dir / 'domain-rules').write_text('exact api.example.com\n')
        self.assertNotEqual(self.run_script('up').returncode, 0)
        self.assertIn('VPN DNS', (self.dir / 'route.error').read_text())
        self.run_script('down')
        self.trace.write_text('')
        self.assertNotEqual(self.run_script('up', CONFLICT='1').returncode, 0)
        self.run_script('down')
        self.assertNotIn('rule del', self.trace.read_text())
        self.assertNotIn('route flush', self.trace.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
