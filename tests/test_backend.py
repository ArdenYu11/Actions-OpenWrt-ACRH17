#!/usr/bin/env python3
"""配置生成及输入边界测试，不需要连接真实 VPN。"""
import os
import pathlib
import shlex
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMON = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client/common.sh'


class BackendTests(unittest.TestCase):
    def run_shell(self, script, directory=None):
        defaults = {
            'server': 'vpn.example.com', 'username': 'test-user',
            'password': 'test-password', 'psk': 'test-psk',
            'ike': 'aes256-sha256-modp2048', 'esp': 'aes256-sha1',
            'local_id': '', 'remote_id': '', 'mtu': '1400',
            'lcp_interval': '30', 'lcp_failure': '5',
            'retry_interval': '30', 'retry_max_attempts': '0', 'probe_ip': '10.20.0.10',
            'routes': '10.20.0.0/16 10.30.0.7/32',
            'routing_mode': 'rules', 'vpn_dns': '', 'domains': '', 'domain_prefixes': '', 'domain_suffixes': '',
            'server_ip': '192.0.2.20', 'local_ip': '192.0.2.10',
        }
        prefix = '\n'.join(f'{key}={shlex.quote(value)}' for key, value in defaults.items())
        if directory:
            prefix += '\nLP_DIR=' + shlex.quote(str(directory))
        return subprocess.run(['sh', '-c', f'. {shlex.quote(str(COMMON))}\n{prefix}\n{script}'],
                              capture_output=True, text=True)

    def test_valid_defaults_and_routes(self):
        result = self.run_shell('lp_validate || { printf "%s" "$LP_ERROR"; exit 1; }')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rejects_invalid_config(self):
        cases = {
            'server': ['https://vpn.example.com', 'x;touch /tmp/injected', '', 'bad\nhost', '10.20.0.1\n10.20.0.2'],
            'password': ['', 'pw\nrefuse-pap'],
            'psk': ['', 'pw\nconnections { evil {} }'],
            'ike': ['aes256-sha256-modp2048\nversion = 2', 'unknown'],
            'routes': ['0.0.0.0/0', '10.0.0.0/33', '999.1.2.3/16', '10.0.0.0;touch /tmp/x'],
            'mtu': ['0', '1461', '1;exit', '999999999999999999'],
            'probe_ip': ['https://example.com', '256.0.0.1', '-option', 'a;touch /tmp/x', 'host:80', 'bad\nhost', '10.20.0.1\n10.20.0.2'],
            'retry_interval': ['0', '3601', '1;exit'], 'retry_max_attempts': ['-1', '10001', 'foo'],
            'routing_mode': ['unknown'], 'vpn_dns': ['bad', '256.0.0.1'],
            'domains': ['https://example.com', '*.example.com', 'example.com/path', '.example.com'],
            'domain_prefixes': ['api..', '*.'], 'domain_suffixes': ['com.', 'foo..com'],
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    result = self.run_shell(f'{key}={shlex.quote(value)}\nlp_validate')
                    self.assertNotEqual(result.returncode, 0)

    def test_render_quotes_permissions_and_protocol(self):
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp)
            password = 'pw "quoted" \\ slash $HOME `date` # ;'
            psk = 'PSK "quote" \\ $HOME $(date) # ;'
            script = f'password={shlex.quote(password)}\npsk={shlex.quote(psk)}\nlp_validate && lp_render'
            result = self.run_shell(script, target)
            self.assertEqual(result.returncode, 0, result.stderr)
            ppp = (target / 'ppp.options').read_text()
            swan = (target / 'swanctl.conf').read_text()
            escaped = lambda text: text.replace('\\', '\\\\').replace('"', '\\"')
            self.assertIn(f'password "{escaped(password)}"', ppp)
            self.assertIn(f'secret = "{escaped(psk)}"', swan)
            self.assertIn('mode = transport', swan)
            self.assertIn('version = 1', swan)
            self.assertIn('remote_ts = 192.0.2.20/32[udp/1701]', swan)
            self.assertIn('nodefaultroute', ppp)
            # 3 秒重发一次，30 次约 90 秒，给手机确认留出时间
            self.assertIn('pap-max-authreq 30', ppp)
            self.assertIn('usepeerdns', ppp)
            for option in ['refuse-eap', 'refuse-chap', 'refuse-mschap', 'refuse-mschap-v2']:
                self.assertIn(option, ppp)
            self.assertNotIn('refuse-pap', ppp)
            for name in ['ppp.options', 'swanctl.conf', 'strongswan.conf']:
                self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), 0o600)
            self.assertEqual((target / 'routes').read_text().splitlines(), ['10.20.0.0/16', '10.30.0.7/32'])

    def test_empty_routes_generate_no_default_route(self):
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp)
            result = self.run_shell('routes=""\nlp_validate && lp_render', target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / 'routes').read_text().strip(), '')

    def test_modes_render_combined_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            target = pathlib.Path(temp)
            result = self.run_shell("domains='api.example.com'\ndomain_prefixes='api. internal-'\ndomain_suffixes='example.org'\nlp_validate && lp_render", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / 'routing-mode').read_text().strip(), 'rules')
            self.assertEqual((target / 'domain-rules').read_text().splitlines(), [
                'exact api.example.com', 'prefix api.', 'prefix internal-', 'suffix example.org'])
            result = self.run_shell("routing_mode=full\ndomains='api.example.com'\nlp_validate && lp_render", target)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((target / 'routing-mode').read_text().strip(), 'full')
            self.assertEqual((target / 'domain-rules').read_text(), '')

    def test_probe_supports_ip_and_domain(self):
        for value in ['10.20.0.10', 'intranet.example.com', 'localhost', 'internal-app.example.org']:
            with self.subTest(value=value):
                self.assertEqual(self.run_shell(f'probe_ip={shlex.quote(value)}\nlp_validate').returncode, 0)

    def test_domain_rule_limit(self):
        value = ' '.join('example.com' for _ in range(513))
        self.assertNotEqual(self.run_shell(f'domains={shlex.quote(value)}\nlp_validate').returncode, 0)

    def test_syntax_and_json(self):
        import json
        for path in (ROOT / 'packages').rglob('*'):
            if not path.is_file():
                continue
            if path.read_text().startswith('#!/bin/sh'):
                result = subprocess.run(['sh', '-n', str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, str(path) + result.stderr)
            elif path.suffix == '.json':
                json.loads(path.read_text())


if __name__ == '__main__':
    unittest.main(verbosity=2)
