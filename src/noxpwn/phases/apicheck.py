import json
import urllib.request
import urllib.error
from .base import BasePhase
from ..utils import info, good, save_to_file, read_file
from ..config import GRAPHQL_PATHS


class Phase11Api(BasePhase):
    name = "API & GraphQL Discovery"
    phase_num = 11

    def run(self, live_hosts):
        self.header()
        api_findings = []
        graphql_endpoints = []

        # Nuclei — API / GraphQL / exposure templates
        nuclei_cmd = self.get_tool_cmd("nuclei")
        if nuclei_cmd and not self.is_skipped("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)
            naf = self.outdir / "nuclei_api.txt"
            nuclei_rf = self.rate_limit_flags("nuclei")
            self.run_tool(
                f"{nuclei_cmd} -l {hosts_file} {nuclei_rf} -tags api,swagger,graphql,exposure -silent -o {naf}",
                timeout=600,
                tool_name="nuclei"
            )
            if naf.exists():
                na = read_file(naf)
                if na:
                    api_findings.extend(na)
                    for line in na[:20]:
                        self.add_finding("medium", f"API exposure: {line.strip()[:120]}")
                    good(f"nuclei api: {len(na)} exposures")

        # Python-based GraphQL detection with SSL-tolerant probe and throttling
        if not self.is_skipped("graphql") and not self.is_skipped("gql"):
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            probe_payload = json.dumps({"query": "{__typename}"}).encode()
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) noxpwn/1.3.0",
            }
            for host in live_hosts[:10]:
                for path in GRAPHQL_PATHS:
                    url = f"{host}{path}"
                    self.engine.throttle()
                    try:
                        req = urllib.request.Request(
                            url, data=probe_payload, method="POST", headers=headers
                        )
                        with urllib.request.urlopen(req, timeout=8, context=ctx) as resp:
                            body = resp.read(65536).decode("utf-8", errors="ignore")
                            if '"__typename"' in body or '"data"' in body:
                                graphql_endpoints.append(f"{url} [200]")
                                self.add_finding("medium", f"GraphQL endpoint: {url} (200)")
                    except urllib.error.HTTPError as e:
                        if e.code == 400:
                            try:
                                body = e.read(65536).decode("utf-8", errors="ignore")
                                if '"__typename"' in body or '"data"' in body or "error" in body.lower():
                                    graphql_endpoints.append(f"{url} [400]")
                                    self.add_finding("medium", f"GraphQL endpoint: {url} (400)")
                            except Exception:
                                pass
                    except Exception:
                        continue

        if graphql_endpoints:
            save_to_file(self.outdir / "graphql_endpoints.txt", graphql_endpoints)
            api_findings.extend(graphql_endpoints)
            good(f"GraphQL endpoints: {len(graphql_endpoints)}")

        if api_findings:
            save_to_file(self.outdir / "api_findings.txt", api_findings)
            good(f"Total API/GraphQL findings: {len(api_findings)}")
        return api_findings


class Phase12ParamUrls(BasePhase):
    name = "Parameterized URL Filtering"
    phase_num = 12

    def run(self, all_urls):
        self.header()
        param_urls = [u for u in all_urls if "=" in u]
        save_to_file(self.outdir / "param_urls.txt", param_urls)
        info(f"URLs with parameters: {len(param_urls)}")

        httpx_cmd = self.get_tool_cmd("httpx")
        if param_urls and httpx_cmd and not self.is_skipped("httpx"):
            uf = self.outdir / "urls.txt"
            save_to_file(uf, param_urls)
            lf = self.outdir / "live_param_urls.txt"
            httpx_rf = self.rate_limit_flags("httpx")
            self.run_tool(f"{httpx_cmd} -l {uf} {httpx_rf} -silent -mc 200 -o {lf}", timeout=300, tool_name="httpx")
            if lf.exists():
                live = read_file(lf)
                if live:
                    good(f"Live param URLs: {len(live)}")
                    return live
        return param_urls
