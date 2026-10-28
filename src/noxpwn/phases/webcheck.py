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

        subzy_cmd = self.get_tool_cmd("subzy")
        if subzy_cmd and not self.is_skipped("subzy"):
            results = self.run_tool(
                f"{subzy_cmd} run --targets {hosts_file} --hide_fails",
                timeout=300,
                tool_name="subzy"
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

        nuclei_cmd = self.get_tool_cmd("nuclei")
        if nuclei_cmd and not self.is_skipped("nuclei"):
            nuc_file = self.outdir / "nuclei_takeover.txt"
            nuc_rf = self.rate_limit_flags("nuclei")
            self.run_tool(
                f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags takeover -silent -o {nuc_file}",
                timeout=600,
                tool_name="nuclei"
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
        waf_results = []
        wafw00f_cmd = self.get_tool_cmd("wafw00f")

        if wafw00f_cmd and not self.is_skipped("wafw00f"):
            for host in live_hosts[:10]:
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                self.engine.throttle()
                rc, out, err = run_cmd(f"{wafw00f_cmd} {host} -a", timeout=60, capture=True, live=False)
                if rc != 0 and any(f in (err + " " + out).lower() for f in ["not recognized", "not found", "winerror 2", "no such file"]):
                    self.mark_tool_failed("wafw00f", "executable failed")
                    break
                if out:
                    for line in out.split("\n"):
                        if "WAF" in line or "waf" in line.lower() or "behind" in line.lower():
                            waf_results.append(f"{clean}: {line.strip()}")
                            info(f"  {line.strip()}")
                elif err and "WAF" in err:
                    for line in err.split("\n"):
                        if "WAF" in line:
                            waf_results.append(f"{clean}: {line.strip()}")
                            info(f"  {line.strip()}")
        else:
            if not self.is_skipped("wafw00f"):
                info("wafw00f not installed. Using built-in HTTP header WAF detector...")
            from ..utils import safe_http_get
            waf_signatures = {
                "Cloudflare": ["cloudflare", "cf-ray", "__cfduid"],
                "AWS CloudFront/WAF": ["cloudfront", "x-amz-cf-id", "awselb"],
                "Akamai": ["akamai", "x-akamai-transformed"],
                "Sucuri": ["sucuri", "x-sucuri-id"],
                "Imperva/Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
                "F5 BIG-IP": ["big-ip", "f5_cspm", "bigipserver"],
            }
            for host in live_hosts[:10]:
                self.engine.throttle()
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                status, _, hdrs = safe_http_get(host, timeout=8)
                if hdrs:
                    hdrs_str = " ".join(f"{k}:{v}" for k, v in hdrs.items()).lower()
                    for waf_name, sigs in waf_signatures.items():
                        if any(sig in hdrs_str for sig in sigs):
                            match_str = f"{clean}: Behind {waf_name}"
                            if match_str not in waf_results:
                                waf_results.append(match_str)
                                good(f"WAF Detected: {clean} -> {waf_name}")
                                self.add_finding("info", f"WAF: {match_str}")

        if waf_results:
            save_to_file(self.outdir / "waf_summary.txt", waf_results)
            good(f"WAF detection completed: {len(waf_results)} findings")
        else:
            info("No WAF detected")


class Phase06Screenshots(BasePhase):
    name = "Screenshot Capture"
    phase_num = 6

    def run(self, live_hosts, important_findings=False):
        self.header()
        gowitness_cmd = self.get_tool_cmd("gowitness")
        if not gowitness_cmd or self.is_skipped("gowitness"):
            if not self.is_skipped("gowitness"):
                warn("gowitness not installed")
            return
        targets = live_hosts if important_findings else live_hosts[:10]
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, targets)
        self.run_tool(
            f"{gowitness_cmd} scan file -f {hosts_file} --screenshot-path {self.outdir}/",
            timeout=300,
            tool_name="gowitness"
        )
        good(f"Screenshots saved: {self.outdir}")
