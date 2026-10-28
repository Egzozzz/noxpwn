import ssl
import urllib.request
import urllib.error
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd, c, safe_http_get


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so we can inspect the Location header directly."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _get_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_status_and_headers(url, method="GET", headers=None, timeout=10):
    """Cross-platform, SSL-tolerant HTTP request returning (status, lowercase headers dict)."""
    try:
        req_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) noxpwn/1.3.0"}
        if headers:
            req_headers.update(headers)
        req = urllib.request.Request(url, method=method, headers=req_headers)
        with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        hdrs = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        return e.code, hdrs
    except Exception:
        return None, {}


def _redirect_location(url, timeout=10):
    """Return the Location header of a request without following redirects (SSL tolerant)."""
    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=_get_ssl_context()),
            _NoRedirect()
        )
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) noxpwn/1.3.0"})
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
        findings = []

        # 1. External CorsMe execution if available and not skipped
        corsme_cmd = self.get_tool_cmd("CorsMe") or self.get_tool_cmd("corsme")
        if corsme_cmd and not self.is_skipped("corsme"):
            info(f"Running CorsMe ({corsme_cmd})...")
            cf = self.outdir / "cors_findings.txt"
            cors_rf = self.rate_limit_flags("corsme")
            tool_out = self.run_tool(
                f"{corsme_cmd} {cors_rf} -wildcard -output {cf}",
                stdin_file=hosts_file,
                timeout=120,
                tool_name="CorsMe"
            )
            if cf.exists():
                file_findings = read_file(cf)
                if file_findings:
                    findings.extend(file_findings)
            if tool_out:
                for line in tool_out:
                    if any(k in line.lower() for k in ["misconfig", "vulnerable", "allow-origin", "origin"]):
                        if line not in findings:
                            findings.append(line)

            if findings:
                for f in findings[:10]:
                    self.add_finding("medium", f"CORS (CorsMe): {f.strip()[:120]}")
                good(f"CorsMe: {len(findings)} misconfigurations found!")
            else:
                info("CorsMe finished: no misconfigurations reported")

        # 2. Built-in Comprehensive Python CORS Engine (always reliable fallback & enrichment)
        if not findings and not self.is_skipped("cors"):
            info("Testing CORS headers via built-in engine (origin reflection & credential leaks)...")
            target_domain = self.engine.domain
            test_origins = [
                "https://evil-attacker.com",
                "null",
                f"https://{target_domain}.evil-attacker.com",
                f"https://evil{target_domain}",
                f"https://{target_domain}_evil.com",
            ]

            for host in live_hosts[:10]:
                for origin in test_origins:
                    self.engine.throttle()
                    # Test both GET and OPTIONS for maximum coverage
                    for method in ("GET", "OPTIONS"):
                        _, hdrs = _http_status_and_headers(
                            host,
                            method=method,
                            headers={"Origin": origin, "Access-Control-Request-Method": "GET"}
                        )
                        if not hdrs:
                            continue

                        acao = hdrs.get("access-control-allow-origin", "")
                        acac = hdrs.get("access-control-allow-credentials", "").lower() == "true"

                        if not acao:
                            continue

                        if origin in acao:
                            if acac:
                                msg = f"{host} reflects {origin} with ACAC:true [{method}]"
                                findings.append(f"[CRITICAL] {msg}")
                                self.add_finding("high", f"Vulnerable CORS (Credentials Allowed): {msg}")
                                good(f"🔥 High Severity CORS: {msg}")
                            else:
                                msg = f"{host} reflects {origin} [{method}]"
                                findings.append(f"[MEDIUM] {msg}")
                                self.add_finding("medium", f"CORS Origin Reflection: {msg}")
                            break
                        elif acao == "*" and acac:
                            msg = f"{host} wildcard ACAO with ACAC:true [{method}]"
                            findings.append(f"[HIGH] {msg}")
                            self.add_finding("high", f"CORS Wildcard with Credentials: {msg}")
                            break
                        elif acao == "*":
                            msg = f"{host} allows wildcard origin (*)"
                            if msg not in findings:
                                findings.append(f"[INFO] {msg}")
                            break

        if findings:
            save_to_file(self.outdir / "cors_findings.txt", findings)
            good(f"Total CORS findings: {len(findings)}")
        else:
            info("No CORS misconfigurations found")
        return findings


class Phase15Nuclei(BasePhase):
    name = "Vulnerability Scan"
    phase_num = 15

    def run(self, live_hosts):
        self.header()
        nuclei_cmd = self.get_tool_cmd("nuclei")
        if not nuclei_cmd or self.is_skipped("nuclei"):
            if not self.is_skipped("nuclei"):
                warn("nuclei not installed")
            return

        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)
        all_vulns = set()
        nuc_rf = self.rate_limit_flags("nuclei")

        # Pass 1: All severity general scan
        info("Nuclei pass 1/4 — vulnerability scan...")
        of = self.outdir / "nuclei_vulns.txt"
        self.run_tool(
            f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -silent -severity critical,high,medium -exclude-severity info -o {of}",
            timeout=900,
            tool_name="nuclei"
        )
        vulns = read_file(of)
        all_vulns.update(vulns)
        if vulns:
            good(f"nuclei (general): {len(vulns)} findings")
            for v in vulns[:10]:
                self.add_finding("high", f"Nuclei: {v.strip()[:120]}")

        if "nuclei" in self.engine.failed_tools:
            return

        # Pass 2: Technology detection (non-critical, for enrichment)
        info("Nuclei pass 2/4 — technology detection...")
        tf = self.outdir / "nuclei_tech.txt"
        self.run_tool(
            f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags tech -silent -o {tf}",
            timeout=300,
            tool_name="nuclei"
        )
        if tf.exists():
            techs = read_file(tf)
            if techs:
                save_to_file(self.outdir / "technologies_detected.txt", techs)
                info(f"Technologies detected: {len(techs)}")

        if "nuclei" in self.engine.failed_tools:
            return

        # Pass 3: CVE-specific scan
        info("Nuclei pass 3/4 — CVE & exploit scanning...")
        cf = self.outdir / "nuclei_cves.txt"
        self.run_tool(
            f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags cve -severity low,medium,high,critical -silent -o {cf}",
            timeout=600,
            tool_name="nuclei"
        )
        if cf.exists():
            cves = read_file(cf)
            if cves:
                all_vulns.update(cves)
                good(f"nuclei (CVE): {len(cves)} CVEs found")
                for v in cves[:10]:
                    self.add_finding("high", f"CVE: {v.strip()[:120]}")

        if "nuclei" in self.engine.failed_tools:
            return

        # Pass 4: Exposure & misconfiguration scan
        info("Nuclei pass 4/4 — exposure & misconfiguration scan...")
        ef = self.outdir / "nuclei_exposures.txt"
        self.run_tool(
            f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags exposure,misconfig,backup,config -silent -o {ef}",
            timeout=600,
            tool_name="nuclei"
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
        dalfox_cmd = self.get_tool_cmd("dalfox")
        if dalfox_cmd and not self.is_skipped("dalfox"):
            info("Running dalfox XSS scanner...")
            df_out = self.outdir / "dalfox_results.txt"
            df_rf = self.rate_limit_flags("dalfox")
            self.run_tool(
                f"{dalfox_cmd} scan {df_rf} --silence --no-color -o {df_out}",
                stdin_file=candidates_file,
                timeout=600,
                tool_name="dalfox"
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
            if not self.is_skipped("dalfox"):
                warn("dalfox not installed. Running reflection test on top candidates...")
            from ..utils import safe_http_get
            import urllib.parse
            canary = "noxpwn_xss_probe"
            for u in candidates[:15]:
                self.engine.throttle()
                # Test reflection
                parsed = urllib.parse.urlparse(u)
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    test_qs = {k: canary for k in qs}
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urllib.parse.urlencode(test_qs), parsed.fragment
                    ))
                    status, body, _ = safe_http_get(test_url, timeout=6)
                    if status and canary in body:
                        self.add_finding("high", f"Reflected parameter: {test_url}")
                        good(f"Reflected parameter found: {test_url}")

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
        sqlmap_cmd = self.get_tool_cmd("sqlmap")
        if sqlmap_cmd and not self.is_skipped("sqlmap"):
            info("Running sqlmap on SQLi candidates...")
            sm_out = self.outdir / "sqlmap"
            sm_rf = self.rate_limit_flags("sqlmap")
            self.run_tool(
                f"{sqlmap_cmd} -m {candidates_file} --batch --risk=3 --level=3 {sm_rf} "
                f"--output-dir={sm_out} --flush-session --random-agent "
                f"--tamper=space2comment",
                timeout=600,
                tool_name="sqlmap"
            )
            if sm_out.is_dir():
                good("sqlmap scan completed — check report in output directory")
                log_files = sum(1 for _ in sm_out.rglob("log"))
                if log_files > 0:
                    self.add_finding("high", f"SQLi: {log_files} potential findings in sqlmap logs")
        else:
            if not self.is_skipped("sqlmap"):
                warn("sqlmap not installed. Manual verification required:")
            for u in candidates[:5]:
                hint = f'sqlmap -u "{u}" --batch --risk=3 --level=3'
                print(f"    {c(hint, 'cyan')}")

        print(f"\n  {c('Top SQLi candidates:', 'bold')}")
        for u in candidates[:10]:
            print(f"    {c('→', 'red')} {u}")

    def run_sqlmap_serial(self, candidates):
        """Fallback: run sqlmap on each URL individually."""
        sm_rf = self.rate_limit_flags("sqlmap")
        for i, url in enumerate(candidates[:5]):
            smd = self.outdir / f"sqlmap_{i}"
            run_cmd(
                f"sqlmap -u \"{url}\" --batch --risk=3 --level=3 {sm_rf} "
                f"--output-dir={smd} --flush-session --random-agent",
                timeout=300,
            )


class Phase18OpenRedirect(BasePhase):
    name = "Open Redirect Detection"
    phase_num = 18

    def run(self, live_hosts):
        self.header()
        nuc_rf = self.rate_limit_flags("nuclei")
        nuclei_cmd = self.get_tool_cmd("nuclei")

        if nuclei_cmd and not self.is_skipped("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)

            info("Scanning for open redirect vulnerabilities with nuclei...")
            rf = self.outdir / "open_redirects.txt"
            self.run_tool(
                f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags redirect -silent -o {rf}",
                timeout=300,
                tool_name="nuclei"
            )

            if rf.exists():
                findings = read_file(rf)
                if findings:
                    good(f"Open redirects: {len(findings)} found!")
                    for f in findings[:10]:
                        self.add_finding("medium", f"Open redirect: {f.strip()[:120]}")
                else:
                    info("No open redirects detected by nuclei")

        # Additional Python-based check for basic redirect patterns
        info("Testing basic redirect parameters...")
        redirect_params = ["url", "redirect", "next", "return", "dest", "redirect_uri", "return_url", "r"]
        test_urls = live_hosts[:3]
        for host in test_urls:
            for param in redirect_params:
                self.engine.throttle()
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
        nuc_rf = self.rate_limit_flags("nuclei")
        nuclei_cmd = self.get_tool_cmd("nuclei")

        # Check with nuclei for exposure templates
        if nuclei_cmd and not self.is_skipped("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)

            info("Scanning for exposed files with nuclei...")
            nf = self.outdir / "nuclei_exposed_files.txt"
            self.run_tool(
                f"{nuclei_cmd} -l {hosts_file} {nuc_rf} -tags exposure,config,backup,git -silent -o {nf}",
                timeout=300,
                tool_name="nuclei"
            )
            if nf.exists():
                nresults = read_file(nf)
                findings.update(nresults)

        # Python-based check for common sensitive files with safe throttling
        info("Checking common sensitive paths via built-in HTTP prober...")
        from ..utils import safe_http_get
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
                self.engine.throttle()
                code, _, _ = safe_http_get(url, timeout=6)
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
