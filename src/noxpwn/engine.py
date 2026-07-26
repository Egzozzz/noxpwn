import os
import re
from datetime import datetime
from pathlib import Path

from .utils import (
    banner, info, good, warn, phase_header, save_to_file, read_file,
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
        self.findings = {"high": [], "medium": [], "low": [], "info": []}
        self.start_time = datetime.now()
        self.timer = Timer()
        self.xss_candidates = []
        self.sqli_candidates = []

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
        for d in sorted(os.listdir(self.base_dir)):
            dp = self.base_dir / d
            if os.path.isdir(dp):
                count = len([f for f in os.listdir(dp) if os.path.isfile(dp / f)])
                lines.append(f"  ├── {d}/ ({count} files)")

        lines.append("")
        if self.xss_candidates:
            lines.append(f" XSS Candidates: {len(self.xss_candidates)}")
        if self.sqli_candidates:
            lines.append(f" SQLi Candidates: {len(self.sqli_candidates)}")

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

        if self.should_run(1):
            subdomains = Phase01Subdomains(self).run()
        if not subdomains:
            warn("No subdomains found, using target directly")
            subdomains = [self.domain]

        if self.should_run(2):
            Phase02Ports(self).run(subdomains)
        if self.should_run(3):
            live_hosts = Phase03Httpx(self).run(subdomains)
        if not live_hosts:
            live_hosts = [f"https://{d}" for d in subdomains[:5]]

        if self.should_run(4):
            Phase04Takeover(self).run(live_hosts)
        if self.should_run(5):
            Phase05Waf(self).run(live_hosts)

        important = bool(self.findings["high"])
        if self.should_run(6):
            Phase06Screenshots(self).run(live_hosts, important_findings=important)

        if self.should_run(7):
            all_urls = Phase07Urls(self).run(live_hosts)
        if self.should_run(8):
            Phase08Js(self).run(all_urls or live_hosts)
        if self.should_run(9) and not self.quick:
            Phase09Directories(self).run(live_hosts)
        if self.should_run(10) and not self.quick:
            Phase10Params(self).run(live_hosts)
        if self.should_run(11) and not self.quick:
            Phase11Api(self).run(live_hosts)
        if self.should_run(12):
            param_urls = Phase12ParamUrls(self).run(all_urls or live_hosts)
        if self.should_run(13):
            Phase13Classify(self).run(param_urls or live_hosts)
        if self.should_run(14) and not self.quick:
            Phase14Cors(self).run(live_hosts)
        if self.should_run(15) and not self.quick:
            Phase15Nuclei(self).run(live_hosts)
        if self.should_run(16):
            Phase16Xss(self).run()
        if self.should_run(17):
            Phase17Sqli(self).run()

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
