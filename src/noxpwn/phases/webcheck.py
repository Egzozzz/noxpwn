import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file


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
                    self.add_finding("high", f"Takeover: {line}")

            save_to_file(self.outdir / "subzy_results.txt", list(findings))
            if findings:
                good(f"subzy: {len(findings)} takeovers!")
            else:
                info("subzy: no takeovers")

        if self.tool_available("nuclei"):
            nuc_file = self.outdir / "nuclei_takeover.txt"
            self.run_tool(
                f"nuclei -l {hosts_file} -tags takeover -silent -o {nuc_file}",
                timeout=600,
            )
            if os.path.exists(nuc_file):
                nuc_results = read_file(nuc_file)
                for r in nuc_results:
                    if r.strip():
                        self.add_finding("high", f"Nuclei takeover: {r}")

        return list(findings)


class Phase05Waf(BasePhase):
    name = "WAF Detection"
    phase_num = 5

    def run(self, live_hosts):
        self.header()
        if not self.tool_available("wafw00f"):
            warn("wafw00f not installed")
            return

        for host in live_hosts[:10]:
            clean = host.replace("https://", "").replace("http://", "").split("/")[0]
            results = self.run_tool(f"wafw00f {host} -a", timeout=60)
            for line in results:
                if "WAF" in line or "waf" in line.lower():
                    save_to_file(self.outdir / f"{clean}.txt", line)
                    info(f"WAF: {line}")


class Phase06Screenshots(BasePhase):
    name = "Screenshot Capture"
    phase_num = 6

    def run(self, live_hosts, important_findings=False):
        self.header()
        if not self.tool_available("gowitness"):
            warn("gowitness not installed")
            return

        if important_findings:
            info("Critical findings detected! Full screenshot mode...")
            targets = live_hosts
        else:
            info("No critical findings. Taking top 5 screenshots...")
            targets = live_hosts[:5]

        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, targets)
        self.run_tool(
            f"gowitness file -f {hosts_file} -P {self.outdir}/ --no-http",
            timeout=300,
        )
        good(f"Screenshots saved: {self.outdir}")
