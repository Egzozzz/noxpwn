import urllib.request
import urllib.error
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd, c


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so we can inspect the Location header directly."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _http_status_and_headers(url, method="GET", headers=None, timeout=10):
    """Cross-platform HTTP request returning (status, lowercase headers dict)."""
    try:
        req = urllib.request.Request(url, method=method, headers=headers or {})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}
    except Exception:
        return None, {}


def _redirect_location(url, timeout=10):
    """Return the Location header of a request without following redirects."""
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = opener.open(req, timeout=timeout)
        return resp.headers.get("Location", "")
    except urllib.error.HTTPError as e:
        return e.headers.get("Location", "")
    except Exception:
        return ""


class Phase14Cors(BasePhase):
    name = "CORS Misconfiguration"
    phase_num = 14

    def run(self, live_hosts):
        self.header()
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)

        if self.tool_available("CorsMe"):
            cf = self.outdir / "cors_findings.txt"
            self.run_tool(f"cat {hosts_file} | CorsMe -t 50 -output {cf}", timeout=120)
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
                    _, hdrs = _http_status_and_headers(host, method="HEAD", headers={"Origin": origin})
                    acao = hdrs.get("access-control-allow-origin")
                    if acao and (origin in acao or "*" in acao):
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
        all_vulns = set()

        # Pass 1: All severity general scan
        info("Nuclei pass 1/4 — vulnerability scan...")
        of = self.outdir / "nuclei_vulns.txt"
        self.run_tool(
            f"nuclei -l {hosts_file} -silent -severity critical,high,medium -exclude-severity info -o {of}",
            timeout=900,
        )
        vulns = read_file(of)
        all_vulns.update(vulns)
        if vulns:
            good(f"nuclei (general): {len(vulns)} findings")
            for v in vulns[:10]:
                self.add_finding("high", f"Nuclei: {v.strip()[:120]}")

        # Pass 2: Technology detection (non-critical, for enrichment)
        info("Nuclei pass 2/4 — technology detection...")
        tf = self.outdir / "nuclei_tech.txt"
        self.run_tool(
            f"nuclei -l {hosts_file} -tags tech -silent -o {tf}",
            timeout=300,
        )
        if tf.exists():
            techs = read_file(tf)
            if techs:
                save_to_file(self.outdir / "technologies_detected.txt", techs)
                info(f"Technologies detected: {len(techs)}")

        # Pass 3: CVE-specific scan
        info("Nuclei pass 3/4 — CVE & exploit scanning...")
        cf = self.outdir / "nuclei_cves.txt"
        self.run_tool(
            f"nuclei -l {hosts_file} -tags cve -severity low,medium,high,critical -silent -o {cf}",
            timeout=600,
        )
        if cf.exists():
            cves = read_file(cf)
            if cves:
                all_vulns.update(cves)
                good(f"nuclei (CVE): {len(cves)} CVEs found")
                for v in cves[:10]:
                    self.add_finding("high", f"CVE: {v.strip()[:120]}")

        # Pass 4: Exposure & misconfiguration scan
        info("Nuclei pass 4/4 — exposure & misconfiguration scan...")
        ef = self.outdir / "nuclei_exposures.txt"
        self.run_tool(
            f"nuclei -l {hosts_file} -tags exposure,misconfig,backup,config -silent -o {ef}",
            timeout=600,
        )
        if ef.exists():
            exposures = read_file(ef)
            if exposures:
                all_vulns.update(exposures)
                good(f"nuclei (exposures): {len(exposures)} exposures found")
                for v in exposures[:10]:
                    self.add_finding("medium", f"Exposure: {v.strip()[:120]}")

        if all_vulns:
            save_to_file(self.outdir / "all_nuclei_findings.txt", sorted(all_vulns))
            good(f"Total nuclei findings: {len(all_vulns)}")
        else:
            good("nuclei: no vulnerabilities found")


class Phase16Xss(BasePhase):
    name = "XSS Analysis"
    phase_num = 16

    def run(self):
        self.header()
        candidates = self.engine.xss_candidates
        if not candidates:
            good("No XSS candidates found")
            return

        warn(f"🔥 {len(candidates)} XSS candidates found!")
        candidates_file = self.outdir / "xss_candidates.txt"
        save_to_file(candidates_file, candidates)

        # Auto-scan with dalfox
        if self.tool_available("dalfox"):
            info("Running dalfox XSS scanner...")
            df_out = self.outdir / "dalfox_results.txt"
            self.run_tool(
                f"cat {candidates_file} | dalfox scan --silence --no-color -o {df_out} 2>/dev/null",
                timeout=600,
            )
            if df_out.exists():
                results = read_file(df_out)
                if results:
                    good(f"dalfox: {len(results)} XSS findings!")
                    for r in results[:10]:
                        self.add_finding("high", f"XSS: {r.strip()[:120]}")
                else:
                    info("dalfox: no XSS verified")
        else:
            warn("dalfox not installed. Manual verification required:")
            print(f"  {c('cat {}/xss_candidates.txt | dalfox scan'.format(self.outdir), 'cyan')}")

        print(f"\n  {c('Top XSS candidates:', 'bold')}")
        for u in candidates[:10]:
            print(f"    {c('→', 'red')} {u}")


class Phase17Sqli(BasePhase):
    name = "SQLi Analysis"
    phase_num = 17

    def run(self):
        self.header()
        candidates = self.engine.sqli_candidates
        if not candidates:
            good("No SQLi candidates found")
            return

        warn(f"🔥 {len(candidates)} SQLi candidates found!")
        candidates_file = self.outdir / "sqli_candidates.txt"
        save_to_file(candidates_file, candidates)

        # Auto-scan with sqlmap
        if self.tool_available("sqlmap"):
            info("Running sqlmap on SQLi candidates...")
            sm_out = self.outdir / "sqlmap"
            self.run_tool(
                f"sqlmap -m {candidates_file} --batch --risk=3 --level=3 "
                f"--output-dir={sm_out} --flush-session --random-agent "
                f"--tamper=space2comment 2>/dev/null",
                timeout=600,
            )
            if sm_out.is_dir():
                good("sqlmap scan completed — check report in output directory")
                # Count log files as approximate finding count
                log_files = sum(1 for _ in sm_out.rglob("log"))
                if log_files > 0:
                    self.add_finding("high", f"SQLi: {log_files} potential findings in sqlmap logs")
        else:
            warn("sqlmap not installed. Manual verification required:")
            for u in candidates[:5]:
                print(f"    {c(f'sqlmap -u \"{u}\" --batch --risk=3 --level=3', 'cyan')}")

        print(f"\n  {c('Top SQLi candidates:', 'bold')}")
        for u in candidates[:10]:
            print(f"    {c('→', 'red')} {u}")

    def run_sqlmap_serial(self, candidates):
        """Fallback: run sqlmap on each URL individually."""
        for i, url in enumerate(candidates[:5]):
            smd = self.outdir / f"sqlmap_{i}"
            run_cmd(
                f"sqlmap -u \"{url}\" --batch --risk=3 --level=3 "
                f"--output-dir={smd} --flush-session --random-agent 2>/dev/null",
                timeout=300,
            )


class Phase18OpenRedirect(BasePhase):
    name = "Open Redirect Detection"
    phase_num = 18

    def run(self, live_hosts):
        self.header()
        if not self.tool_available("nuclei"):
            warn("nuclei not installed, skipping redirect scan")
            return

        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)

        info("Scanning for open redirect vulnerabilities...")
        rf = self.outdir / "open_redirects.txt"
        self.run_tool(
            f"nuclei -l {hosts_file} -tags redirect -silent -o {rf}",
            timeout=300,
        )

        if rf.exists():
            findings = read_file(rf)
            if findings:
                good(f"Open redirects: {len(findings)} found!")
                for f in findings[:10]:
                    self.add_finding("medium", f"Open redirect: {f.strip()[:120]}")
            else:
                info("No open redirects detected")

        # Additional curl-based check for basic redirect patterns
        info("Testing basic redirect parameters...")
        redirect_params = ["url", "redirect", "next", "return", "dest", "redirect_uri", "return_url", "r"]
        test_urls = live_hosts[:3]
        for host in test_urls:
            for param in redirect_params:
                url = f"{host}?{param}=https://evil.com"
                location = _redirect_location(url)
                if location and "evil.com" in location:
                    self.add_finding("medium", f"Open redirect: {host}?{param}=https://evil.com")
                    save_to_file(self.outdir / "redirect_params_found.txt", f"{host}?{param}=https://evil.com")
                    break


class Phase19ExposedFiles(BasePhase):
    name = "Exposed Files & Directories"
    phase_num = 19

    def run(self, live_hosts):
        self.header()
        findings = set()

        # Check with nuclei for exposure templates
        if self.tool_available("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)

            info("Scanning for exposed files with nuclei...")
            nf = self.outdir / "nuclei_exposed_files.txt"
            self.run_tool(
                f"nuclei -l {hosts_file} -tags exposure,config,backup,git -silent -o {nf}",
                timeout=300,
            )
            if nf.exists():
                nresults = read_file(nf)
                findings.update(nresults)

        # Curl-based check for common sensitive files
        info("Checking common sensitive paths via curl...")
        sensitive_paths = [
            "/.git/config", "/.env", "/.env.example", "/.gitignore",
            "/backup", "/backup.zip", "/backup.tar.gz", "/wp-config.php",
            "/config.php", "/config.json", "/database.yml",
            "/admin/", "/phpinfo.php", "/info.php", "/.htaccess",
            "/server-status", "/crossdomain.xml", "/sitemap.xml",
            "/robots.txt", "/Dockerfile", "/docker-compose.yml",
            "/.aws/credentials", "/.gitlab-ci.yml", "/.svn/entries",
            "/WEB-INF/web.xml", "/actuator/", "/swagger.json",
        ]
        for host in live_hosts[:5]:
            for path in sensitive_paths:
                url = f"{host}{path}"
                code, _ = _http_status_and_headers(url)
                if code in (200, 401, 403):
                    finding = f"{url} [{code}]"
                    findings.add(finding)
                    sev = "high" if path in ("/.git/config", "/.env", "/.aws/credentials", "/wp-config.php") else "medium"
                    self.add_finding(sev, f"Exposed: {url} ({code})")
                    info(f"  {finding}")

        if findings:
            save_to_file(self.outdir / "exposed_files.txt", sorted(findings))
            good(f"Exposed items: {len(findings)}")
        else:
            info("No exposed files found")
