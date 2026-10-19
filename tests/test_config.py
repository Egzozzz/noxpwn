import unittest
from src.noxpwn.config import get_rate_limit_flags, find_wordlist, TOOL_CONFIG


class TestConfig(unittest.TestCase):
    def test_rate_limit_flags_httpx(self):
        flags = get_rate_limit_flags("httpx", rate_limit=10, threads=5)
        self.assertIn("-rate-limit 10", flags)
        self.assertIn("-threads 5", flags)

    def test_rate_limit_flags_nuclei(self):
        flags = get_rate_limit_flags("nuclei", rate_limit=5, threads=15)
        self.assertIn("-rate-limit 5", flags)
        self.assertIn("-concurrency 15", flags)

    def test_rate_limit_flags_katana(self):
        flags = get_rate_limit_flags("katana", rate_limit=8, threads=4, delay=0.5)
        self.assertIn("-rate-limit 8", flags)
        self.assertIn("-concurrency 4", flags)
        self.assertIn("-delay 0.5", flags)

    def test_rate_limit_flags_ffuf(self):
        flags = get_rate_limit_flags("ffuf", rate_limit=20, threads=10)
        self.assertIn("-rate 20", flags)
        self.assertIn("-t 10", flags)

    def test_rate_limit_flags_feroxbuster(self):
        flags = get_rate_limit_flags("feroxbuster", rate_limit=15, threads=8)
        self.assertIn("--rate-limit 15", flags)
        self.assertIn("-t 8", flags)

    def test_rate_limit_flags_dalfox(self):
        flags = get_rate_limit_flags("dalfox", threads=5, delay=0.5)
        self.assertIn("--worker 5", flags)
        self.assertIn("--delay 500", flags)

    def test_rate_limit_flags_sqlmap(self):
        flags = get_rate_limit_flags("sqlmap", threads=3, delay=1.0)
        self.assertIn("--threads=3", flags)
        self.assertIn("--delay=1.0", flags)

    def test_rate_limit_flags_none(self):
        flags = get_rate_limit_flags("httpx")
        self.assertEqual(flags, "")

    def test_tool_config_keys(self):
        self.assertIn("httpx", TOOL_CONFIG)
        self.assertIn("nuclei", TOOL_CONFIG)
        self.assertIn("subfinder", TOOL_CONFIG)
        self.assertIn("katana", TOOL_CONFIG)


if __name__ == "__main__":
    unittest.main()
