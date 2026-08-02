from .base import BasePhase
from ..utils import good, warn, save_to_file, read_file, c


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
