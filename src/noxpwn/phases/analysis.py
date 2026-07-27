from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, c


class Phase13Classify(BasePhase):
    name = "Pattern Classification"
    phase_num = 13

    def run(self, param_urls):
        self.header()

        if not self.tool_available("gf"):
            warn("gf not installed. Using basic regex matching.")
            xss = [u for u in param_urls if any(p in u.lower() for p in ["q=", "s=", "search=", "query=", "id=", "page="])]
            sqli = [u for u in param_urls if any(p in u.lower() for p in ["id=", "page=", "cat=", "product=", "view="])]
        else:
            urls_file = self.outdir / "urls.txt"
            save_to_file(urls_file, param_urls)
            xss = []
            sqli = []
            patterns = ["xss", "sqli", "rce", "lfi", "ssrf", "redirect", "rfi", "ssti"]

            for pattern in patterns:
                out_file = self.outdir / f"gf_{pattern}.txt"
                output = self.run_tool(
                    f"cat {urls_file} | gf {pattern} > {out_file}",
                    timeout=60,
                )
                matched = read_file(out_file)
                if matched:
                    good(f"gf {pattern}: {len(matched)} URLs")
                    if pattern == "xss":
                        xss = matched
                    elif pattern == "sqli":
                        sqli = matched

        if xss:
            save_to_file(self.outdir / "xss_candidates.txt", xss)
            self.engine.xss_candidates = xss
            self.add_finding("medium", f"XSS candidates: {len(xss)}")
            warn("Potential XSS detected! Check manually:")
            for u in xss[:5]:
                print(f"    → {c(u, 'yellow')}")

        if sqli:
            save_to_file(self.outdir / "sqli_candidates.txt", sqli)
            self.engine.sqli_candidates = sqli
            self.add_finding("medium", f"SQLi candidates: {len(sqli)}")
            warn("Potential SQLi detected! Check manually:")
            for u in sqli[:5]:
                print(f"    → {c(u, 'yellow')}")

        return {"xss": xss, "sqli": sqli}
