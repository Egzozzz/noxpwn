import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure project root is in sys.path
root_dir = str(Path(__file__).resolve().parent.parent)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.noxpwn.engine import NoxPwnEngine


class TestEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_engine_init_with_rate_limit(self):
        config = {
            "rate_limit": 5,
            "threads": 4,
            "delay": 0.2,
            "quick": True,
        }
        engine = NoxPwnEngine("https://example.com", self.temp_dir, config)
        self.assertEqual(engine.domain, "example.com")
        self.assertEqual(engine.rate_limit, 5)
        self.assertEqual(engine.threads, 4)
        self.assertEqual(engine.delay, 0.2)
        self.assertTrue(engine.quick)

    def test_engine_delay_auto_calculation(self):
        config = {
            "rate_limit": 10,
        }
        engine = NoxPwnEngine("https://test.local", self.temp_dir, config)
        self.assertEqual(engine.delay, 0.1)

    def test_engine_add_finding(self):
        engine = NoxPwnEngine("https://example.com", self.temp_dir)
        engine.add_finding("high", "Test Finding", "Finding details", "Phase 1")
        self.assertEqual(len(engine.findings["high"]), 1)
        self.assertEqual(engine.findings["high"][0]["title"], "Test Finding")

    def test_generate_report(self):
        engine = NoxPwnEngine("https://example.com", self.temp_dir)
        engine.add_finding("high", "XSS Found", "in param q", "Phase 16")
        lines = engine.generate_report()
        report_file = Path(self.temp_dir) / "example.com" / "report" / "scan_report.txt"
        self.assertTrue(report_file.exists())
        content = report_file.read_text(encoding="utf-8")
        self.assertIn("NOXPWN - SCAN REPORT", content)
        self.assertIn("XSS Found", content)


    def test_engine_rejects_command_injection(self):
        dangerous_targets = [
            "https://example.com; rm -rf /",
            "https://example.com && whoami",
            "https://example.com | cat /etc/passwd",
            "https://example.com`id`",
            "https://example.com$(whoami)",
            "https://example.com > output.txt",
        ]
        for dt in dangerous_targets:
            with self.assertRaises(ValueError):
                NoxPwnEngine(dt, self.temp_dir)

    def test_engine_auto_prepends_https(self):
        engine = NoxPwnEngine("example.com", self.temp_dir)
        self.assertEqual(engine.target, "https://example.com")
        self.assertEqual(engine.domain, "example.com")


if __name__ == "__main__":
    unittest.main()
