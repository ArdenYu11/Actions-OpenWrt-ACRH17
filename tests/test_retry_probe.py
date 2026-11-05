#!/usr/bin/env python3
"""重连上限、循环间隔及 IP/域名探测行为验证。"""
import pathlib
import shlex
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
COMMON = ROOT / 'packages/l2tp-ipsec-client/files/usr/lib/l2tp-ipsec-client/common.sh'


class RetryProbeTests(unittest.TestCase):
    def shell(self, script):
        return subprocess.run(['sh', '-c', '. ' + shlex.quote(str(COMMON)) + '\n' + script],
                              text=True, capture_output=True)

    def test_cyclic_fibonacci_and_non_sequence_cap(self):
        for cap, expected in [(8, [1, 2, 3, 5, 8, 1, 2, 3, 5, 8]),
                              (6, [1, 2, 3, 5, 6, 1, 2, 3, 5, 6]),
                              (1, [1] * 10), (2, [1, 2] * 5)]:
            with self.subTest(cap=cap):
                result = self.shell(f'''retry_interval={cap}; retry_max_attempts=0; lp_retry_reset
for step in 1 2 3 4 5 6 7 8 9 10; do lp_retry_plan || exit 1; echo "$retry_wait"; done''')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual([int(v) for v in result.stdout.split()], expected)

    def test_limit_reset_and_leading_zero_numbers(self):
        result = self.shell('''retry_interval=00008; retry_max_attempts=00003; lp_retry_reset
lp_retry_plan && lp_retry_plan && lp_retry_plan || exit 1
lp_retry_plan && exit 2
printf '%s %s\n' "$retry_attempt" "$retry_wait"
lp_retry_reset
lp_retry_plan || exit 3
printf '%s %s\n' "$retry_attempt" "$retry_wait"''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['3 3', '1 1'])

    def probe(self, target, resolved='10.20.1.5', route=True, ping=True):
        return self.shell(f'''
probe_ip={shlex.quote(target)}
resolveip() {{ printf '%s\\n' {shlex.quote(resolved)}; }}
ip() {{ {'echo "10.20.1.5 dev l2tp-vpn src 10.20.0.1"' if route else 'echo "10.20.1.5 via 192.0.2.1 dev wan"'}; }}
ping() {{ {'return 0' if ping else 'return 1'}; }}
lp_probe
printf '%s|%s\\n' "$LP_PROBE_REACH" "$LP_PROBE_ADDRESS"
''')

    def test_ip_and_domain_probe_results(self):
        for target in ['10.20.1.5', 'intranet.example.com']:
            self.assertEqual(self.probe(target).stdout.strip(), 'yes|10.20.1.5')
        self.assertEqual(self.probe('intranet.example.com', route=False).stdout.strip(), 'no_route|10.20.1.5')
        self.assertEqual(self.probe('intranet.example.com', ping=False).stdout.strip(), 'no|10.20.1.5')
        self.assertEqual(self.probe('intranet.example.com', resolved='').stdout.strip(), 'resolve_failed|')
        self.assertEqual(self.probe('intranet.example.com', resolved='malformed').stdout.strip(), 'resolve_failed|')

    def test_multihomed_domain_checks_valid_vpn_address(self):
        result = self.shell('''probe_ip=intranet.example.com
resolveip() { printf '%s\\n' 192.0.2.5 10.20.1.5; }
ip() { case "$4" in 10.20.1.5) echo '10.20.1.5 dev l2tp-vpn' ;; *) echo '192.0.2.5 dev wan' ;; esac; }
ping() { return 0; }
lp_probe
printf '%s|%s\\n' "$LP_PROBE_REACH" "$LP_PROBE_ADDRESS"''')
        self.assertEqual(result.stdout.strip(), 'yes|10.20.1.5')


if __name__ == '__main__':
    unittest.main(verbosity=2)
