import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file


class Phase02Ports(BasePhase):
    name = "Port & Service Scanning"
    phase_num = 2

    def run(self, subdomains):
        self.header()
        subs_file = self.outdir / "targets.txt"
        save_to_file(subs_file, subdomains)
        open_ports = []

        # naabu — port scanning (top 1000)
        if self.tool_available("naabu"):
            naabu_out = self.outdir / "naabu_ports.txt"
            self.run_tool(
                f"naabu -list {subs_file} -silent -top-ports 1000 -o {naabu_out}",
                timeout=600,
            )
            if naabu_out.exists():
                open_ports = read_file(naabu_out)
                good(f"naabu: {len(open_ports)} open ports (top 1000)")

        # nmap — service + script scan on discovered ports
        if self.tool_available("nmap") and open_ports:
            # naabu outputs host:port — extract unique hosts for nmap
            hosts = sorted(set(line.split(":")[0].strip() for line in open_ports if ":" in line))
            targets_file = self.outdir / "nmap_targets.txt"
            save_to_file(targets_file, hosts)
            self.run_tool(
                f"nmap -sV -sC -T4 -iL {targets_file} -oN {self.outdir}/nmap_scan.txt",
                timeout=900,
            )
            good("nmap service+script scan complete")
        elif self.tool_available("nmap") and not open_ports:
            # No open ports from naabu, scan top ports directly
            info("naabu found no ports. Running nmap on top 100 ports...")
            self.run_tool(
                f"nmap -sV -sC -T4 --top-ports 100 -iL {subs_file} -oN {self.outdir}/nmap_scan.txt",
                timeout=600,
            )
            if os.path.exists(self.outdir / "nmap_scan.txt"):
                good("nmap scan complete")

        return open_ports


class Phase03Httpx(BasePhase):
    name = "Live Host Detection"
    phase_num = 3

    def run(self, subdomains):
        self.header()
        subs_file = self.outdir / "subs.txt"
        save_to_file(subs_file, subdomains)
        live_hosts = []

        if self.tool_available("httpx"):
            live_file = self.outdir / "live_hosts.txt"
            self.run_tool(
                f"httpx -l {subs_file} -silent -tech-detect -status-code -content-length -title -web-server -o {live_file}",
                timeout=600,
            )
            if live_file.exists():
                raw = read_file(live_file)
                for line in raw:
                    if line.startswith("http"):
                        live_hosts.append(line.split()[0])
                if live_hosts:
                    good(f"httpx: {len(live_hosts)} live hosts")

                    # Extract technologies
                    techs = set()
                    for line in raw:
                        for part in line.split():
                            if part.startswith("[") and part.endswith("]"):
                                for t in part.strip("[]").split(","):
                                    techs.add(t.strip())
                    if techs:
                        save_to_file(self.outdir / "technologies.txt", sorted(techs))
                        info(f"Tech detected: {', '.join(sorted(techs)[:20])}")
        else:
            live_hosts = [f"https://{d}" for d in subdomains[:10]]
            warn("httpx not available, using raw domains")

        save_to_file(self.outdir / "live_urls.txt", live_hosts)
        return live_hosts
