import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('baseline', Path(__file__).parents[1] / 'scripts/baseline.py')
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)

class BaselineTests(unittest.TestCase):
    def test_spaces_boundary_and_native_group(self):
        sample = '''PID RSS COMM
1 1024 /fixture/SecureLink.app/Contents/MacOS/SecureLink
2 2048 /fixture/SecureLink.app/Contents/Frameworks/SecureLink Helper (GPU).app/Contents/MacOS/Helper
3 512 /fixture/SecureLink.app/Contents/Resources/app.asar.unpacked/assets/app-ext/securelink_mac/bin/SecureLink_Client
4 999999 /fixture/SecureLink.app.evil/fake
5 999999 /unrelated/app'''
        result = baseline.summarize(sample, '/fixture/SecureLink.app')
        self.assertEqual(result['totals_kib'], {'electron': 3072, 'native': 512})
        self.assertEqual(result['process_count'], 3)
    def test_absent_is_unknown(self):
        result = baseline.summarize('', '/fixture/SecureLink.app')
        self.assertEqual(result['process_count'], 0)
        self.assertIn('does not prove', result['limitation'])
    def test_malformed_selected_row_fails(self):
        with self.assertRaises(ValueError):
            baseline.summarize('1 invalid /fixture/SecureLink.app/bin', '/fixture/SecureLink.app')

if __name__ == '__main__': unittest.main()
