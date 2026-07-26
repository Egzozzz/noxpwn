import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, check_tool as util_check_tool


class Phase02Ports(BasePhase):
    name = "Port & Service Scanning"
    phase_num = 2

    def run(self, subdomains):
        self.header()
        subs_file = self.outdir / "targets.txt"
        save_to_file(subs_file, subdomains)
        open_ports = []

        if util_check_tool("naabu"):
            naabu_out = self.outdir / "naabu_ports.txt"
            self.run_tool(
                f"naabu -list {subs_file} -silent -o {naabu_out}",
                timeout=600,
            )
            if os.path.exists(naabu_out):
                open_ports = read_file(naabu_out)
                good(f"naabu: {len(open_ports)} open ports")

        if util_check_tool("nmap") and open_ports:
            targets_file = self.outdir / "nmap_targets.txt"
            save_to_file(targets_file, open_ports)
            self.run_tool(
                f"nmap -sV -T4 -iL {targets_file} -oN {self.outdir}/nmap_scan.txt",
                timeout=900,
            )
            good("nmap service scan complete")

        return open_ports


class Phase03Httpx(BasePhase):
    name = "Live Host Detection"
    phase_num = 3

    def run(self, subdomains):
        self.header()
        subs_file = self.outdir / "subs.txt"
        save_to_file(subs_file, subdomains)

        live_hosts = []
        if util_check_tool("httpx"):
            live_file = self.outdir / "live_hosts.txt"
            self.run_tool(
                f"httpx -l {subs_file} -silent -tech-detect -status-code -o {live_file}",
                timeout=600,
            )
            if os.path.exists(live_file):
                live_hosts = read_file(live_file)
                good(f"httpx: {len(live_hosts)} live hosts")

                techs = set()
                for line in live_hosts:
                    parts = line.split("[")
                    if len(parts) > 1:
                        tech_str = parts[-1].rstrip("]")
                        for t in tech_str.split(","):
                            techs.add(t.strip())
                if techs:
                    save_to_file(self.outdir / "technologies.txt", sorted(techs))
                    info(f"Tech stack: {', '.join(sorted(techs)[:15])}")
        else:
            live_hosts = [f"https://{d}" for d in subdomains[:5]]
            warn("httpx not available, using raw domains")

        return live_hosts
