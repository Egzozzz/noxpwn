import os
import json
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, check_tool as util_check_tool
from ..config import find_wordlist


class Phase09Directories(BasePhase):
    name = "Directory Bruteforce"
    phase_num = 9

    def run(self, live_hosts):
        self.header()
        wordlist = find_wordlist()
        found_paths = set()

        if not wordlist:
            warn("No wordlist found. Using basic wordlist.")
            basic = ["admin", "api", "backup", "config", "css", "js",
                     "images", "login", "logout", "robots.txt", "sitemap.xml",
                     "test", "static", "assets", "uploads", "private", "secret",
                     "dashboard", "wp-admin", ".git", ".env", "phpinfo.php"]
            save_to_file(self.outdir / "wordlist.txt", basic)
            wordlist = f"{self.outdir}/wordlist.txt"

        info(f"Using wordlist: {wordlist}")

        if util_check_tool("ffuf"):
            for host in live_hosts[:3]:
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                ffuf_out = f"{self.outdir}/ffuf_{clean}.json"
                self.run_tool(
                    f"ffuf -u {host}/FUZZ -w {wordlist} -mc 200,301,302,401,403 -t 50 -silent -o {ffuf_out}",
                    timeout=300,
                )
                if os.path.exists(ffuf_out):
                    try:
                        with open(ffuf_out) as f:
                            data = json.load(f)
                            for r in data.get("results", []):
                                found_paths.add(r.get("url", ""))
                    except:
                        pass

        if util_check_tool("feroxbuster"):
            for host in live_hosts[:3]:
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                self.run_tool(
                    f"feroxbuster -u {host} -w {wordlist} -t 30 --silent -o {self.outdir}/ferox_{clean}.txt",
                    timeout=300,
                )

        save_to_file(self.outdir / "found_paths.txt", sorted(found_paths))
        if found_paths:
            good(f"Discovered {len(found_paths)} paths")
            for p in list(found_paths)[:10]:
                info(f"  → {p}")
        return list(found_paths)


class Phase10Params(BasePhase):
    name = "Parameter Discovery"
    phase_num = 10

    def run(self, live_hosts):
        self.header()
        if not util_check_tool("arjun"):
            warn("arjun not installed")
            return

        for host in live_hosts[:5]:
            clean = host.replace("https://", "").replace("http://", "").split("/")[0]
            self.run_tool(
                f"arjun -u {host} -o {self.outdir}/arjun_{clean}.json --quiet",
                timeout=300,
            )
            if os.path.exists(f"{self.outdir}/arjun_{clean}.json"):
                good(f"Arjun params saved for {clean}")
