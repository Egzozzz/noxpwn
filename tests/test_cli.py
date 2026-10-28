import unittest
from src.noxpwn.__main__ import normalize_skip_tools, TOOL_ALIASES


class TestCli(unittest.TestCase):
    def test_normalize_empty(self):
        self.assertEqual(normalize_skip_tools([]), set())
        self.assertEqual(normalize_skip_tools(None), set())

    def test_normalize_comma_separated(self):
        res = normalize_skip_tools(["cors,nuclei,ffuf"])
        self.assertIn("cors", res)
        self.assertIn("corsme", res)
        self.assertIn("nuclei", res)
        self.assertIn("ffuf", res)

    def test_normalize_space_separated(self):
        res = normalize_skip_tools(["corsme", "linkfinder", "arjun"])
        self.assertIn("corsme", res)
        self.assertIn("cors", res)
        self.assertIn("linkfinder", res)
        self.assertIn("lf", res)
        self.assertIn("arjun", res)

    def test_normalize_aliases(self):
        # crtsh -> crt.sh
        res = normalize_skip_tools(["crtsh"])
        self.assertIn("crt.sh", res)
        self.assertIn("crtsh", res)

        # wf -> wafw00f
        res2 = normalize_skip_tools(["wf"])
        self.assertIn("wafw00f", res2)
        self.assertIn("waf", res2)

        # sqli -> sqlmap
        res3 = normalize_skip_tools(["sqli"])
        self.assertIn("sqlmap", res3)

        # xss -> dalfox
        res4 = normalize_skip_tools(["xss"])
        self.assertIn("dalfox", res4)

        # gql -> graphql
        res5 = normalize_skip_tools(["gql"])
        self.assertIn("graphql", res5)


if __name__ == "__main__":
    unittest.main()
