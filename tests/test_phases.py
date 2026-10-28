import os
import shutil
import tempfile
import unittest
from pathlib import Path
from src.noxpwn.engine import NoxPwnEngine
from src.noxpwn.phases.base import BasePhase
from src.noxpwn.phases import (
    Phase01Subdomains, Phase03Httpx, Phase08Js, Phase16Xss, Phase17Sqli
)


class TestPhases(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.engine = NoxPwnEngine("https://target.local", self.temp_dir, {
            "rate_limit": 10,
            "threads": 5,
            "delay": 0.1
        })

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_base_phase_rate_limit_flags(self):
        phase = BasePhase(self.engine)
        httpx_flags = phase.rate_limit_flags("httpx")
        self.assertIn("-rate-limit 10", httpx_flags)
        self.assertIn("-threads 5", httpx_flags)

        katana_flags = phase.rate_limit_flags("katana")
        self.assertIn("-rate-limit 10", katana_flags)
        self.assertIn("-concurrency 5", katana_flags)
        self.assertIn("-delay 0.1", katana_flags)

    def test_phase_header_creates_dir(self):
        phase = Phase01Subdomains(self.engine)
        phase.header()
        self.assertTrue(phase.outdir.exists())

    def test_xss_empty_candidates(self):
        phase = Phase16Xss(self.engine)
        phase.run()
        self.assertEqual(len(self.engine.findings["high"]), 0)

    def test_tool_skipping(self):
        self.engine.skip_tools = {"corsme", "linkfinder", "crt.sh"}
        phase = BasePhase(self.engine)
        self.assertTrue(phase.is_skipped("corsme"))
        self.assertTrue(phase.is_skipped("CorsMe"))
        self.assertTrue(phase.is_skipped("linkfinder"))
        self.assertFalse(phase.tool_available("corsme"))
        self.assertIsNone(phase.get_tool_cmd("corsme"))

    def test_tool_failure_circuit_breaker(self):
        phase = BasePhase(self.engine)
        # Manually trigger failure marking
        phase.mark_tool_failed("faketool", "not found")
        self.assertIn("faketool", self.engine.failed_tools)
        self.assertFalse(phase.tool_available("faketool"))
        self.assertIsNone(phase.get_tool_cmd("faketool"))

        # run_tool with a non-existent command should auto-mark it as failed
        res = phase.run_tool("nonexistent_binary_xyz_12345 --help", timeout=5)
        self.assertEqual(res, [])
        self.assertIn("nonexistent_binary_xyz_12345", self.engine.failed_tools)


if __name__ == "__main__":
    unittest.main()
