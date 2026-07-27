import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd
from ..config import GRAPHQL_PATHS, find_api_wordlist


class Phase11Api(BasePhase):
    name = "API & GraphQL Discovery"
    phase_num = 11

    def run(self, live_hosts):
        self.header()
        api_findings = []

        # x8 — hidden API path discovery
        if self.tool_available("x8"):
            api_wl = find_api_wordlist()
            if not api_wl:
                basic_api = [
                    "api", "api/v1", "api/v2", "v1", "v2", "v3",
                    "graphql", "swagger", "docs", "rest", "api-docs",
                    "swagger.json", "openapi.json", "health", "status",
                    "users", "admin", "login", "auth", "token", "oauth",
                ]
                api_wl = str(self.outdir / "api_wordlist.txt")
                save_to_file(api_wl, basic_api)

            for host in live_hosts[:5]:
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                x8f = self.outdir / f"x8_api_{clean}.txt"
                self.run_tool(f"x8 -u {host} -w {api_wl} -o {x8f} --silent", timeout=300)
                if x8f.exists():
                    xr = read_file(x8f)
                    if xr:
                        api_findings.extend(xr)
                        for line in xr[:5]:
                            self.add_finding("low", f"API endpoint: {line.strip()[:120]}")
                        good(f"x8 API ({clean}): {len(xr)} endpoints")

        # Nuclei — GraphQL detection
        if self.tool_available("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            save_to_file(hosts_file, live_hosts)
            ngf = self.outdir / "nuclei_graphql.txt"
            self.run_tool(
                f"nuclei -l {hosts_file} -tags graphql -silent -o {ngf}",
                timeout=300,
            )
            if ngf.exists():
                ng = read_file(ngf)
                if ng:
                    api_findings.extend(ng)
                    for line in ng:
                        self.add_finding("medium", f"GraphQL: {line.strip()[:120]}")
                    good(f"nuclei graphql: {len(ng)} endpoints")

        # Nuclei — API-related templates
        if self.tool_available("nuclei"):
            hosts_file = self.outdir / "targets.txt"
            naf = self.outdir / "nuclei_api.txt"
            self.run_tool(
                f"nuclei -l {hosts_file} -tags api,swagger,exposure -silent -o {naf}",
                timeout=300,
            )
            if naf.exists():
                na = read_file(naf)
                if na:
                    api_findings.extend(na)
                    for line in na:
                        self.add_finding("medium", f"API exposure: {line.strip()[:120]}")
                    good(f"nuclei api: {len(na)} exposures")

        # Basic curl-based GraphQL detection
        for host in live_hosts[:10]:
            for path in GRAPHQL_PATHS:
                _, out, _ = run_cmd(
                    f"curl -sk -o /dev/null -w '%{{http_code}}' '{host}{path}' 2>/dev/null",
                    timeout=10,
                )
                if out.strip() in ("200", "400"):
                    status = "200 OK" if out.strip() == "200" else "400 (GraphQL likely)"
                    self.add_finding("medium", f"GraphQL endpoint: {host}{path} ({status})")
                    save_to_file(self.outdir / "graphql_endpoints.txt", f"{host}{path}")

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

        if param_urls and self.tool_available("httpx"):
            uf = self.outdir / "urls.txt"
            save_to_file(uf, param_urls)
            lf = self.outdir / "live_param_urls.txt"
            self.run_tool(f"httpx -l {uf} -silent -mc 200 -o {lf}", timeout=300)
            if lf.exists():
                live = read_file(lf)
                if live:
                    good(f"Live param URLs: {len(live)}")
                    return live
        return param_urls
