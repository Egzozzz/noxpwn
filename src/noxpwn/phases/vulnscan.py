import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd, c


class Phase14Cors(BasePhase):
    name = "CORS Misconfiguration"
    phase_num = 14

    def run(self, live_hosts):
        self.header()
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)

        if self.tool_available("CorsMe"):
            cf = self.outdir / "cors_findings.txt"
            self.run_tool(f"CorsMe -i {hosts_file} -o {cf}", timeout=120)
            if cf.exists():
                findings = read_file(cf)
                if findings:
                    for f in findings[:10]:
                        self.add_finding("medium", f"CORS: {f.strip()[:120]}")
                    good(f"CorsMe: {len(findings)} misconfigurations")
                else:
                    info("CORS: no issues found")
        else:
            warn("CorsMe not installed. Running basic check...")
            origins = ["https://evil.com", "null", "https://evil.com:80", "https://evil.com:443"]
            for host in live_hosts[:5]:
                for origin in origins:
                    _, out, _ = run_cmd(
                        f"curl -s -I -H 'Origin: {origin}' '{host}' 2>/dev/null",
                        timeout=10,
                    )
                    if "Access-Control-Allow-Origin" in out:
                        if origin in out or "*" in out:
                            self.add_finding("medium", f"CORS misconfig: {host} (origin: {origin})")


class Phase15Nuclei(BasePhase):
    name = "Vulnerability Scan"
    phase_num = 15

    def run(self, live_hosts):
        self.header()
        if not self.tool_available("nuclei"):
            warn("nuclei not installed")
            return

        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)
        of = self.outdir / "nuclei_vulns.txt"

        info("Scanning with nuclei (critical/high/medium)...")
        self.run_tool(
            f"nuclei -l {hosts_file} -severity critical,high,medium -silent -o {of}",
            timeout=900,
        )

        vulns = read_file(of)
        if vulns:
            good(f"nuclei: {len(vulns)} vulnerabilities found!")
            for v in vulns[:20]:
                self.add_finding("high", f"Nuclei: {v.strip()[:120]}")
        else:
            good("nuclei: no vulnerabilities found")


class Phase16Xss(BasePhase):
    name = "XSS Analysis"
    phase_num = 16

    def run(self):
        self.header()
        candidates = self.engine.xss_candidates
        if candidates:
            warn(f"🔥 {len(candidates)} XSS candidates found!")
            print(f"\n  {c('Verify with dalfox:', 'yellow')}")
            print(f"    {c('dalfox url <URL> --pipe', 'cyan')}")
            print(f"    {c('dalfox file {}/xss_candidates.txt --pipe'.format(self.outdir), 'cyan')}")
            print(f"\n  {c('Top candidates:', 'bold')}")
            for u in candidates[:10]:
                print(f"    {c('→', 'red')} {u}")
        else:
            good("No XSS candidates found")


class Phase17Sqli(BasePhase):
    name = "SQLi Analysis"
    phase_num = 17

    def run(self):
        self.header()
        candidates = self.engine.sqli_candidates
        if candidates:
            warn(f"🔥 {len(candidates)} SQLi candidates found!")
            print(f"\n  {c('Verify with sqlmap:', 'yellow')}")
            for u in candidates[:5]:
                print(f"    {c(f'sqlmap -u \"{u}\" --batch --risk=3 --level=3', 'cyan')}")
            print(f"\n  {c('Top candidates:', 'bold')}")
            for u in candidates[:10]:
                print(f"    {c('→', 'red')} {u}")
        else:
            good("No SQLi candidates found")
