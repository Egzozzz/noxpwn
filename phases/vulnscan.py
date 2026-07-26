import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, check_tool as util_check_tool, run_cmd, c


class Phase14Cors(BasePhase):
    name = "CORS Misconfiguration"
    phase_num = 14

    def run(self, live_hosts):
        self.header()

        if util_check_tool("corsy"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)
            out_file = self.outdir / "cors_findings.txt"
            self.run_tool(
                f"python3 -m corsy -i {hosts_file} -o {out_file}",
                timeout=120,
            )
            if os.path.exists(out_file):
                findings = read_file(out_file)
                if findings:
                    self.add_finding("medium", f"CORS issues: {len(findings)}")
                    good(f"CORS: {len(findings)} misconfigs")
                else:
                    info("CORS: no issues found")
        else:
            warn("corsy not installed. Running basic check...")
            for host in live_hosts[:5]:
                _, out, _ = run_cmd(
                    f"curl -s -I -H 'Origin: https://evil.com' '{host}'",
                    timeout=10,
                )
                if "Access-Control-Allow-Origin" in out and "evil" in out:
                    self.add_finding("medium", f"CORS misconfig: {host}")


class Phase15Nuclei(BasePhase):
    name = "Vulnerability Scan"
    phase_num = 15

    def run(self, live_hosts):
        self.header()
        if not util_check_tool("nuclei"):
            warn("nuclei not installed")
            return

        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)
        out_file = self.outdir / "nuclei_vulns.txt"

        info("Scanning with nuclei (critical/high/medium)...")
        self.run_tool(
            f"nuclei -l {hosts_file} -severity critical,high,medium -silent -o {out_file}",
            timeout=900,
        )

        vulns = read_file(out_file)
        if vulns:
            good(f"nuclei: {len(vulns)} vulnerabilities!")
            for v in vulns[:15]:
                self.add_finding("high", f"Nuclei: {v[:120]}")
        else:
            good("nuclei: no findings")


class Phase16Xss(BasePhase):
    name = "XSS Analysis"
    phase_num = 16

    def run(self):
        self.header()
        if self.engine.xss_candidates:
            warn(f"🔥 {len(self.engine.xss_candidates)} XSS candidates!")
            print(f"\n  {c('Manual test with dalfox:', 'yellow')}")
            print(f"    {c('dalfox url <URL> --pipe', 'cyan')}")
            print(f"    {c('dalfox file {}/xss_candidates.txt --pipe'.format(self.outdir), 'cyan')}")
            print(f"\n  {c('Top candidates:', 'bold')}")
            for u in self.engine.xss_candidates[:10]:
                print(f"    {c('→', 'red')} {u}")
        else:
            good("No XSS candidates found")


class Phase17Sqli(BasePhase):
    name = "SQLi Analysis"
    phase_num = 17

    def run(self):
        self.header()
        if self.engine.sqli_candidates:
            warn(f"🔥 {len(self.engine.sqli_candidates)} SQLi candidates!")
            print(f"\n  {c('Manual test with sqlmap:', 'yellow')}")
            print(f"    {c('sqlmap -u \"<URL>\" --batch --risk=3 --level=3', 'cyan')}")
            print(f"\n  {c('Top candidates:', 'bold')}")
            for u in self.engine.sqli_candidates[:10]:
                print(f"    {c('→', 'red')} {u}")
        else:
            good("No SQLi candidates found")
