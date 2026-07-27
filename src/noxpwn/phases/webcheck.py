import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd


class Phase04Takeover(BasePhase):
    name = "Subdomain Takeover"
    phase_num = 4

    def run(self, live_hosts):
        self.header()
        hosts_file = self.outdir / "live_hosts.txt"
        save_to_file(hosts_file, live_hosts)
        findings = set()

        if self.tool_available("subzy"):
            results = self.run_tool(
                f"subzy run --targets {hosts_file} --hide_fails --vuln",
                timeout=300,
            )
            for line in results:
                if "vulnerable" in line.lower() or "takeover" in line.lower():
                    findings.add(line.strip())
                    self.add_finding("high", f"Takeover: {line.strip()[:120]}")
            save_to_file(self.outdir / "subzy_results.txt", list(findings))
            if findings:
                good(f"subzy: {len(findings)} takeovers!")
            else:
                info("subzy: no takeovers found")

        if self.tool_available("nuclei"):
            nuc_file = self.outdir / "nuclei_takeover.txt"
            self.run_tool(
                f"nuclei -l {hosts_file} -tags takeover -silent -o {nuc_file}",
                timeout=600,
            )
            if nuc_file.exists():
                nuc_results = read_file(nuc_file)
                for r in nuc_results:
                    if r.strip():
                        self.add_finding("high", f"Nuclei takeover: {r.strip()[:120]}")
                        findings.add(r.strip())
        return list(findings)


class Phase05Waf(BasePhase):
    name = "WAF Detection"
    phase_num = 5

    def run(self, live_hosts):
        self.header()
        if not self.tool_available("wafw00f"):
            warn("wafw00f not installed, skipping")
            return
        waf_results = []
        for host in live_hosts[:10]:
            clean = host.replace("https://", "").replace("http://", "").split("/")[0]
            rc, out, err = run_cmd(f"wafw00f {host} -a", timeout=60, capture=True, live=False)
            if out:
                for line in out.split("\n"):
                    if "WAF" in line or "waf" in line.lower():
                        waf_results.append(f"{clean}: {line.strip()}")
                        info(f"  {line.strip()}")
            elif err and "WAF" in err:
                for line in err.split("\n"):
                    if "WAF" in line:
                        waf_results.append(f"{clean}: {line.strip()}")
                        info(f"  {line.strip()}")
        if waf_results:
            save_to_file(self.outdir / "waf_summary.txt", waf_results)


class Phase06Screenshots(BasePhase):
    name = "Screenshot Capture"
    phase_num = 6

    def run(self, live_hosts, important_findings=False):
        self.header()
        if not self.tool_available("gowitness"):
            warn("gowitness not installed")
            return
        targets = live_hosts if important_findings else live_hosts[:10]
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, targets)
        self.run_tool(
            f"gowitness file -f {hosts_file} -P {self.outdir}/ --no-http",
            timeout=300,
        )
        good(f"Screenshots saved: {self.outdir}")
