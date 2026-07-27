import os
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file


class Phase01Subdomains(BasePhase):
    name = "Subdomain Discovery"
    phase_num = 1

    def run(self):
        self.header()
        all_subs = set()

        tools = [
            ("subfinder", f"subfinder -d {self.engine.domain} -silent"),
            ("assetfinder", f"assetfinder --subs-only {self.engine.domain}"),
        ]

        if self.tool_available("amass"):
            tools.append(("amass", f"amass enum -passive -d {self.engine.domain} -o {self.outdir}/amass_raw.txt"))

        for name, cmd in tools:
            self.run_tool(cmd, timeout=300)
            out_file = self.outdir / f"{name}.txt"
            if os.path.exists(out_file):
                subs = [l.strip().lower() for l in read_file(out_file) if l.strip()]
            else:
                subs = []
            all_subs.update(subs)
            if subs:
                good(f"{name}: {len(subs)} subdomains")

        final = sorted(all_subs)
        save_to_file(self.outdir / "all_subs.txt", final)
        good(f"Total unique subdomains: {len(final)}")
        return final
