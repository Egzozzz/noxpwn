import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd
from ..config import GRAPHQL_PATHS, find_kiterunner_wordlist


class Phase11Api(BasePhase):
    name = "API & GraphQL"
    phase_num = 11

    def run(self, live_hosts):
        self.header()

        if self.tool_available("kiterunner"):
            kr_wl = find_kiterunner_wordlist()
            if kr_wl:
                hosts_file = self.outdir / "targets.txt"
                save_to_file(hosts_file, live_hosts)
                self.run_tool(
                    f"kiterunner scan -w {kr_wl} -l {hosts_file} -o {self.outdir}/kiterunner_out.txt",
                    timeout=600,
                )
                if os.path.exists(f"{self.outdir}/kiterunner_out.txt"):
                    good("Kiterunner done")
            else:
                warn("kiterunner wordlist not found")

        if self.tool_available("graphw00f"):
            for host in live_hosts[:5]:
                self.run_tool(
                    f"python3 -m graphw00f.main -t {host} -d",
                    timeout=60,
                )

        for host in live_hosts:
            for path in GRAPHQL_PATHS:
                _, out, _ = run_cmd(
                    f"curl -sk -o /dev/null -w '%{{http_code}}' '{host}{path}' 2>/dev/null",
                    timeout=10,
                )
                if out.strip() == "200":
                    self.add_finding("medium", f"GraphQL: {host}{path}")
                    save_to_file(self.outdir / "graphql_endpoints.txt", f"{host}{path}")


class Phase12ParamUrls(BasePhase):
    name = "Parameterized URLs"
    phase_num = 12

    def run(self, all_urls):
        self.header()

        param_urls = [u for u in all_urls if "=" in u]
        save_to_file(self.outdir / "param_urls.txt", param_urls)
        info(f"URLs with params: {len(param_urls)}")

        if param_urls and self.tool_available("httpx"):
            urls_file = self.outdir / "urls.txt"
            save_to_file(urls_file, param_urls)
            live_file = self.outdir / "live_param_urls.txt"
            self.run_tool(
                f"httpx -l {urls_file} -silent -mc 200 -o {live_file}",
                timeout=300,
            )
            if os.path.exists(live_file):
                live = read_file(live_file)
                if live:
                    good(f"Live param URLs: {len(live)}")
                    return live

        return param_urls
