import unittest
from pathlib import Path
from detector import analyze

HEADER = 'timestamp,user,ip,status\n'
def data(rows):
    return HEADER + '\n'.join(f'2026-11-17 {t},{user},{ip},{status}' for t,user,ip,status in rows)
def row(time, user='admin', ip='192.0.2.10', status='failed'):
    return (time, user, ip, status)

class DetectionTests(unittest.TestCase):
    def rules(self, rows):
        return [a['rule'] for a in analyze(data(rows))['alerts']]
    def test_sample(self):
        r=analyze(Path(__file__).with_name('sample.csv').read_text())
        self.assertEqual(r['summary'],dict(events=12,failures=9,ips=3,alerts=4))
    def test_inclusive_boundary(self):
        self.assertEqual(self.rules([row('10:00:00'),row('10:02:00'),row('10:05:00')]),['BURST'])
    def test_outside_window(self):
        self.assertEqual(self.rules([row('10:00:00'),row('10:02:00'),row('10:05:01')]),[])
    def test_account_isolation(self):
        self.assertNotIn('SUCCESS_AFTER_FAILURES',self.rules([row('10:00:00','a'),row('10:01:00','b'),row('10:02:00','c'),row('10:03:00','a',status='success')]))
    def test_success_reset(self):
        rules=self.rules([row('10:00:00'),row('10:01:00'),row('10:02:00'),row('10:03:00',status='success'),row('10:04:00',status='success')])
        self.assertEqual(rules.count('SUCCESS_AFTER_FAILURES'),1)
    def test_rearm(self):
        rules=self.rules([row(t) for t in ['10:00:00','10:01:00','10:02:00','10:03:00','11:00:00','11:01:00','11:02:00']])
        self.assertEqual(rules,['BURST','BURST'])
    def test_sorting(self):
        self.assertEqual(self.rules([row('10:04:00'),row('10:02:00'),row('10:00:00')]),['BURST'])
    def test_different_ips(self):
        self.assertEqual(self.rules([row('10:00:00',ip='192.0.2.1'),row('10:01:00',ip='192.0.2.2'),row('10:02:00',ip='192.0.2.3')]),[])
    def test_bad_status(self):
        with self.assertRaisesRegex(ValueError,'CSV row 2'):
            analyze(data([row('10:00:00',status='unknown')]))
    def test_bad_header(self):
        with self.assertRaises(ValueError): analyze('foo,bar\nx,y')
    def test_bad_ip(self):
        with self.assertRaises(ValueError): analyze(data([row('10:00:00',ip='invalid')]))
    def test_empty(self):
        with self.assertRaises(ValueError): analyze(HEADER)
    def test_bad_settings(self):
        with self.assertRaises(ValueError): analyze(data([row('10:00:00')]),threshold=0)
    def test_bom(self):
        self.assertEqual(analyze('\ufeff'+data([row('10:00:00')]))['summary']['events'],1)

if __name__ == '__main__': unittest.main()
