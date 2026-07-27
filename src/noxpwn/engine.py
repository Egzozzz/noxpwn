import os
import re
import traceback
from datetime import datetime
from pathlib import Path

from .utils import (
    banner, info, good, warn, error, phase_header, save_to_file, read_file,
    check_tool, ensure_dir, c
)
from .progress import Timer
from .phases import (
    Phase01Subdomains, Phase02Ports, Phase03Httpx,
    Phase04Takeover, Phase05Waf, Phase06Screenshots,
    Phase07Urls, Phase08Js,
    Phase09Directories, Phase10Params,
    Phase11Api, Phase12ParamUrls,
    Phase13Classify,
    Phase14Cors, Phase15Nuclei, Phase16Xss, Phase17Sqli,
)


class NoxPwnEngine:
    def __init__(self, target, output_dir, config=None):
        self.target = target
        raw = target.replace("https://", "").replace("http://", "").split("/")[0]
        self.domain = re.sub(r'[^a-zA-Z0-9._-]', '', raw)
        self.base_dir = Path(output_dir) / self.domain
        self.config = config or {}
        self.quick = self.config.get("quick", False)
        self.from_phase = self.config.get("from_phase", 1)
        self.skip_tools = set(self.config.get("skip_tools", []))
        self.findings = {"high": [], "medium": [], "low": [], "info": []}
        self.start_time = datetime.now()
        self.timer = Timer()
        self.xss_candidates = []
        self.sqli_candidates = []
        self.lfi_candidates = []
        self.ssrf_candidates = []
        self.rce_candidates = []
        ensure_dir(self.base_dir)

    def should_run(self, phase_num):
        return phase_num >= self.from_phase

    def add_finding(self, severity, title, detail, phase):
        entry = {
            "title": title,
            "detail": detail,
            "phase": phase,
            "timestamp": datetime.now().isoformat(),
        }
        self.findings[severity].append(entry)
        color_map = {"high": "red", "medium": "yellow", "low": "blue", "info": "cyan"}
        icon_map = {"high": "🔥", "medium": "⚠", "low": "ℹ", "info": "→"}
        print(f"  {c(icon_map[severity], color_map[severity])} {c(f'[{severity.upper()}]', color_map[severity])} {title}")

    def safe_run_phase(self, phase_obj, *args, **kwargs):
        try:
            return phase_obj.run(*args, **kwargs)
        except Exception as e:
            error(f"Phase {phase_obj.phase_num} ({phase_obj.name}) failed: {e}")
            if self.config.get("verbose", False):
                traceback.print_exc()
            return None

    def generate_report(self):
        outdir = ensure_dir(self.base_dir / "report")
        elapsed = datetime.now() - self.start_time

        lines = []
        lines.append("=" * 60)
        lines.append(" NOXPWN - SCAN REPORT")
        lines.append("=" * 60)
        lines.append(f" Target:     {self.target}")
        lines.append(f" Domain:     {self.domain}")
        lines.append(f" Start:      {self.start_time.isoformat()}")
        lines.append(f" Duration:   {elapsed.total_seconds():.1f}s")
        lines.append(f" Output:     {self.base_dir}")
        lines.append("")

        total = sum(len(v) for v in self.findings.values())
        lines.append(f" Total Findings: {total}")
        for sev in ["high", "medium", "low", "info"]:
            items = self.findings[sev]
            if items:
                lines.append(f"  [{sev.upper()}] {len(items)}")
                for i, item in enumerate(items[:10], 1):
                    lines.append(f"    {i}. {item['title'][:100]}")

        lines.append("")
        lines.append(" Directory Structure:")
        lines.append(f"  {self.base_dir}")
        if os.path.exists(self.base_dir):
            for d in sorted(os.listdir(self.base_dir)):
                dp = self.base_dir / d
                if os.path.isdir(dp):
                    count = len([f for f in os.listdir(dp) if os.path.isfile(dp / f)])
                    lines.append(f"  ├── {d}/ ({count} files)")

        lines.append("")
        for name, items in [("XSS", self.xss_candidates), ("SQLi", self.sqli_candidates),
                            ("LFI", self.lfi_candidates), ("SSRF", self.ssrf_candidates),
                            ("RCE", self.rce_candidates)]:
            if items:
                lines.append(f" {name} Candidates: {len(items)}")

        report_path = outdir / "scan_report.txt"
        save_to_file(report_path, "\n".join(lines))
        good(f"Report saved: {report_path}")
        return lines

    def run(self):
        print(banner())
        info(f"Target: {c(self.target, 'bold')}")
        info(f"Output: {c(str(self.base_dir), 'bold')}")
        info(f"Started: {self.start_time.isoformat()}")
        if self.quick:
            info(f"Mode: {c('QUICK', 'yellow')} (skip slow scans)")
        print()

        subdomains = []
        live_hosts = []
        all_urls = []
        param_urls = []

        # === PHASE 1: Subdomains ===
        if self.should_run(1):
            result = self.safe_run_phase(Phase01Subdomains(self))
            if result:
                subdomains = result
        if not subdomains:
            warn("No subdomains found, using target directly")
            subdomains = [self.domain]

        # === PHASE 2: Ports ===
        if self.should_run(2):
            self.safe_run_phase(Phase02Ports(self), subdomains)

        # === PHASE 3: Live Hosts ===
        if self.should_run(3):
            result = self.safe_run_phase(Phase03Httpx(self), subdomains)
            if result:
                live_hosts = result
        if not live_hosts:
            live_hosts = [f"https://{d}" for d in subdomains[:5]]

        # === PHASE 4: Takeover ===
        if self.should_run(4):
            self.safe_run_phase(Phase04Takeover(self), live_hosts)

        # === PHASE 5: WAF ===
        if self.should_run(5):
            self.safe_run_phase(Phase05Waf(self), live_hosts)

        # === PHASE 6: Screenshots ===
        important = bool(self.findings["high"])
        if self.should_run(6):
            self.safe_run_phase(Phase06Screenshots(self), live_hosts, important_findings=important)

        # === PHASE 7: URL Collection ===
        if self.should_run(7):
            result = self.safe_run_phase(Phase07Urls(self), live_hosts)
            if result:
                all_urls = result

        # === PHASE 8: JS Analysis ===
        if self.should_run(8):
            self.safe_run_phase(Phase08Js(self), all_urls or live_hosts)

        # === PHASE 9: Directory Bruteforce ===
        if self.should_run(9) and not self.quick:
            result = self.safe_run_phase(Phase09Directories(self), live_hosts)
            if result:
                # Feed discovered paths back as URLs for deeper scanning
                all_urls.extend(result)

        # === PHASE 10: Parameter Discovery ===
        if self.should_run(10) and not self.quick:
            self.safe_run_phase(Phase10Params(self), live_hosts)

        # === PHASE 11: API & GraphQL ===
        if self.should_run(11) and not self.quick:
            self.safe_run_phase(Phase11Api(self), live_hosts)

        # === PHASE 12: Param URLs ===
        if self.should_run(12):
            result = self.safe_run_phase(Phase12ParamUrls(self), all_urls or live_hosts)
            if result:
                param_urls = result

        # === PHASE 13: Pattern Classification ===
        if self.should_run(13):
            result = self.safe_run_phase(Phase13Classify(self), param_urls or live_hosts)
            if result:
                self.xss_candidates = result.get("xss", [])
                self.sqli_candidates = result.get("sqli", [])
                self.lfi_candidates = result.get("lfi", [])
                self.ssrf_candidates = result.get("ssrf", [])
                self.rce_candidates = result.get("rce", [])

        # === PHASE 14: CORS ===
        if self.should_run(14) and not self.quick:
            self.safe_run_phase(Phase14Cors(self), live_hosts)

        # === PHASE 15: Nuclei ===
        if self.should_run(15) and not self.quick:
            self.safe_run_phase(Phase15Nuclei(self), live_hosts)

        # === PHASE 16: XSS ===
        if self.should_run(16):
            self.safe_run_phase(Phase16Xss(self))

        # === PHASE 17: SQLi ===
        if self.should_run(17):
            self.safe_run_phase(Phase17Sqli(self))

        report = self.generate_report()

        print()
        print(f" {c('═' * 55, 'green')}")
        print(f" {c('✅ NOXPWN SCAN COMPLETE', 'bold')}")
        print(f" {c('═' * 55, 'green')}")
        print(f"  Output: {c(str(self.base_dir), 'cyan')}")
        print(f"  Duration: {c(self.timer.summary(), 'yellow')}")
        print(f"  High: {c(str(len(self.findings['high'])), 'red')}  Medium: {c(str(len(self.findings['medium'])), 'yellow')}  Low: {c(str(len(self.findings['low'])), 'blue')}")
        print()

        return self.findings
