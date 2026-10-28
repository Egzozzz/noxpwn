import os
import json
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file
from ..config import find_wordlist, find_api_wordlist, find_param_wordlist


class Phase09Directories(BasePhase):
    name = "Directory Bruteforce"
    phase_num = 9

    def run(self, live_hosts):
        self.header()
        found_paths = set()

        # Discovery wordlist
        wordlist = find_wordlist()
        if not wordlist:
            basic = [
                "admin", "api", "backup", "config", ".git", ".env", "robots.txt",
                "sitemap.xml", "login", "dashboard", "wp-admin", "test",
                "static", "assets", "uploads", "private", "secret",
                "api/v1", "api/v2", "graphql", "swagger", "docs", "v1", "v2",
            ]
            wordlist = str(self.outdir / "wordlist.txt")
            save_to_file(wordlist, basic)
        info(f"Using wordlist: {wordlist}")

        # API wordlist for API-specific fuzzing
        api_wordlist = find_api_wordlist()

        # ffuf — recursive directory brute-force
        ffuf_cmd = self.get_tool_cmd("ffuf")
        if ffuf_cmd and not self.is_skipped("ffuf"):
            ffuf_rf = self.rate_limit_flags("ffuf")
            for host in live_hosts[:3]:
                if "ffuf" in self.engine.failed_tools:
                    break
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                ffuf_out = f"{self.outdir}/ffuf_{clean}.json"
                self.run_tool(
                    f"{ffuf_cmd} -u {host}/FUZZ -w {wordlist} {ffuf_rf} -mc 200,204,301,302,307,401,403,405,500,501 "
                    f"-recursion -recursion-depth 2 -maxtime 300 -s -of json -o {ffuf_out}",
                    timeout=600,
                    tool_name="ffuf"
                )
                if os.path.exists(ffuf_out):
                    try:
                        with open(ffuf_out) as f:
                            data = json.load(f)
                            results = data.get("results", [])
                            for r in results:
                                url = r.get("url", "")
                                if url:
                                    found_paths.add(url)
                            if results:
                                good(f"ffuf ({clean}): {len(results)} paths")
                    except:
                        pass

            # Additional ffuf pass with API wordlist if available
            if api_wordlist and "ffuf" not in self.engine.failed_tools:
                for host in live_hosts[:3]:
                    if "ffuf" in self.engine.failed_tools:
                        break
                    clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                    ffuf_api_out = f"{self.outdir}/ffuf_api_{clean}.json"
                    self.run_tool(
                        f"{ffuf_cmd} -u {host}/FUZZ -w {api_wordlist} {ffuf_rf} -mc 200,204,301,302,307,401,403,405,500,501 "
                        f"-s -of json -o {ffuf_api_out}",
                        timeout=300,
                        tool_name="ffuf"
                    )
                    if os.path.exists(ffuf_api_out):
                        try:
                            with open(ffuf_api_out) as f:
                                data = json.load(f)
                                for r in data.get("results", []):
                                    url = r.get("url", "")
                                    if url:
                                        found_paths.add(url)
                        except:
                            pass

        # feroxbuster — deeper scan
        ferox_cmd = self.get_tool_cmd("feroxbuster")
        if ferox_cmd and not self.is_skipped("feroxbuster"):
            ferox_rf = self.rate_limit_flags("feroxbuster")
            for host in live_hosts[:2]:
                if "feroxbuster" in self.engine.failed_tools:
                    break
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                ferox_out = self.outdir / f"ferox_{clean}.txt"
                self.run_tool(
                    f"{ferox_cmd} -u {host} -w {wordlist} {ferox_rf} -d 3 --auto-tune "
                    f"--silent -o {ferox_out}",
                    timeout=300,
                    tool_name="feroxbuster"
                )
                if ferox_out.exists():
                    fr = read_file(ferox_out)
                    for line in fr:
                        if "=>" in line and not line.startswith("#"):
                            path = line.split("=>")[0].strip()
                            if path:
                                found_paths.add(path)

        save_to_file(self.outdir / "found_paths.txt", sorted(found_paths))
        if found_paths:
            good(f"Total discovered paths: {len(found_paths)}")
            for p in list(found_paths)[:15]:
                info(f"  → {p}")
        return list(found_paths)


class Phase10Params(BasePhase):
    name = "Parameter Discovery"
    phase_num = 10

    def run(self, live_hosts):
        self.header()
        param_results = {}

        # Arjun — passive + active parameter discovery
        arjun_cmd = self.get_tool_cmd("arjun")
        if arjun_cmd and not self.is_skipped("arjun"):
            for host in live_hosts[:5]:
                if "arjun" in self.engine.failed_tools:
                    break
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                outf = self.outdir / f"arjun_{clean}.json"
                self.run_tool(
                    f"{arjun_cmd} -u {host} -m GET -oJ {outf}",
                    timeout=300,
                    tool_name="arjun"
                )
                if outf.exists():
                    param_results[clean] = str(outf)
                    try:
                        with open(outf) as f:
                            data = json.load(f)
                            total_params = sum(len(v) for v in data.values())
                            good(f"Arjun ({clean}): {total_params} parameters discovered")
                    except:
                        good(f"Arjun params saved for {clean}")

        # x8 — hidden parameter discovery
        x8_cmd = self.get_tool_cmd("x8")
        if x8_cmd and not self.is_skipped("x8"):
            param_wl = find_param_wordlist()
            if not param_wl:
                # Built-in x8 wordlist or basic params
                basic_params = [
                    "id", "page", "file", "path", "url", "redirect", "return",
                    "next", "token", "key", "secret", "auth", "session",
                    "debug", "test", "admin", "user", "pass", "search", "q",
                ]
                param_wl = str(self.outdir / "param_wordlist.txt")
                save_to_file(param_wl, basic_params)

            for host in live_hosts[:3]:
                if "x8" in self.engine.failed_tools:
                    break
                clean = host.replace("https://", "").replace("http://", "").split("/")[0]
                x8f = self.outdir / f"x8_{clean}.txt"
                self.run_tool(
                    f"{x8_cmd} -u {host.rstrip('/') + '/'} -w {param_wl} -o {x8f} --disable-progress-bar",
                    timeout=300,
                    tool_name="x8"
                )
                if x8f.exists():
                    xr = read_file(x8f)
                    if xr:
                        param_results[f"x8_{clean}"] = xr
                        good(f"x8 ({clean}): {len(xr)} hidden params discovered")

        return param_results
