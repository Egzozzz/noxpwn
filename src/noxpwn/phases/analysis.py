import re
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, c


SECRET_REGEXES = [
    ("AWS Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret", r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]"),
    ("Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Google OAuth", r"ya29\.[0-9A-Za-z\-_]+"),
    ("Slack Token", r"xox[baprs]-[0-9a-zA-Z\-]{10,48}"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,255}"),
    ("GitHub Old", r"github\.com/.{1,100}['\"][0-9a-zA-Z]{35,40}['\"]"),
    ("JWT Token", r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    ("Generic API Key", r"(?i)(api[_-]?key|apikey|api[_-]?secret|api_secret)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,}['\"]"),
    ("Bearer Token", r"bearer\s+[A-Za-z0-9\-\._~\+\/]{20,}"),
    ("Private Key", r"-----BEGIN\s?(RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----"),
    ("Firebase URL", r"[a-z0-9-]+\.firebaseio\.com"),
    ("Slack Webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
    ("S3 Bucket", r"[a-z0-9\-\.]+\.s3\.amazonaws\.com"),
    ("Admin Panel", r"(?i)(admin|dashboard|wp-admin|cpanel|phpmyadmin)"),
]


class Phase13Classify(BasePhase):
    name = "Pattern Classification"
    phase_num = 13

    def run(self, param_urls):
        self.header()
        if not param_urls:
            warn("No parameterized URLs to classify")
            return {"xss": [], "sqli": [], "lfi": [], "ssrf": [], "rce": []}

        xss = []
        sqli = []
        lfi = []
        ssrf = []
        rce = []
        idor = []

        # GF Pattern Classification
        if self.tool_available("gf"):
            uf = self.outdir / "urls.txt"
            save_to_file(uf, param_urls)
            patterns = ["xss", "sqli", "rce", "lfi", "ssrf", "redirect", "rfi", "ssti", "idor"]
            for pattern in patterns:
                of = self.outdir / f"gf_{pattern}.txt"
                self.run_tool(f"cat {uf} | gf {pattern} > {of}", timeout=60)
                matched = read_file(of)
                if matched:
                    good(f"gf {pattern}: {len(matched)} URLs matched")
                    if pattern == "xss":
                        xss = matched
                    elif pattern == "sqli":
                        sqli = matched
                    elif pattern == "lfi":
                        lfi = matched
                    elif pattern == "ssrf":
                        ssrf = matched
                    elif pattern == "rce":
                        rce = matched
                    elif pattern == "idor":
                        idor = matched
        else:
            warn("gf not installed. Using regex pattern matching.")
            xss = [u for u in param_urls if any(p in u.lower() for p in ["q=", "s=", "search=", "query=", "text=", "keyword="])]
            sqli = [u for u in param_urls if any(p in u.lower() for p in ["id=", "page=", "cat=", "product=", "view=", "pid="])]
            lfi = [u for u in param_urls if any(p in u.lower() for p in ["file=", "path=", "include=", "template=", "load=", "page="])]
            ssrf = [u for u in param_urls if any(p in u.lower() for p in ["url=", "uri=", "redirect=", "next=", "href=", "src="])]

        # Save results
        if xss:
            save_to_file(self.outdir / "xss_candidates.txt", xss)
            self.add_finding("medium", f"XSS candidates: {len(xss)}")
            warn("Potential XSS detected:")
            for u in xss[:5]:
                print(f"    → {c(u, 'yellow')}")
        if sqli:
            save_to_file(self.outdir / "sqli_candidates.txt", sqli)
            self.add_finding("medium", f"SQLi candidates: {len(sqli)}")
            warn("Potential SQLi detected:")
            for u in sqli[:5]:
                print(f"    → {c(u, 'yellow')}")

        return {"xss": xss, "sqli": sqli, "lfi": lfi, "ssrf": ssrf, "rce": rce}
