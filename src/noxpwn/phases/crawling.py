import os
import re
import shutil
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd, ensure_dir


def _resolve_cmd(tool, module_name=None, script_path=None):
    if shutil.which(tool):
        return tool
    if module_name:
        rc, _, _ = run_cmd(f"python3 -c \"import {module_name}\" 2>/dev/null", capture=True)
        if rc == 0:
            return f"python3 -m {module_name}"
    if script_path and os.path.exists(script_path):
        return f"python3 {script_path}"
    return tool


def _extract_params_from_urls(urls):
    """Extract unique parameter names from a list of URLs."""
    params = set()
    for u in urls:
        if "?" in u:
            qs = u.split("?", 1)[1].split("#")[0]
            for pair in qs.split("&"):
                if "=" in pair:
                    params.add(pair.split("=", 1)[0])
    return sorted(params)


class Phase07Urls(BasePhase):
    name = "URL Collection"
    phase_num = 7

    def run(self, live_hosts):
        self.header()
        all_urls = set()
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)

        # Katana (recursive crawl)
        if self.tool_available("katana"):
            kf = self.outdir / "katana.txt"
            self.run_tool(
                f"katana -list {hosts_file} -silent -recursion -depth 3 -jc -kf all -o {kf}",
                timeout=600,
            )
            if kf.exists():
                urls = read_file(kf)
                all_urls.update(urls)
                good(f"katana (recursive): {len(urls)} URLs")

        # Gau (getallurls)
        if self.tool_available("gau"):
            for host in live_hosts[:5]:
                h = host.replace("https://", "").replace("http://", "").split("/")[0]
                gf = self.outdir / f"gau_{h}.txt"
                self.run_tool(f"gau --subs {h} --o {gf}", timeout=300)
                if gf.exists():
                    urls = read_file(gf)
                    all_urls.update(urls)
                    good(f"gau ({h}): {len(urls)} URLs")

        # Waybackurls
        if self.tool_available("waybackurls"):
            wf = self.outdir / "waybackurls.txt"
            self.run_tool(f"cat {hosts_file} | waybackurls > {wf}", timeout=300)
            if wf.exists():
                urls = read_file(wf)
                all_urls.update(urls)
                good(f"waybackurls: {len(urls)} URLs")

        # Hakrawler
        if self.tool_available("hakrawler"):
            for host in live_hosts[:3]:
                h = host.replace("https://", "").replace("http://", "").split("/")[0]
                hf = self.outdir / f"hakrawler_{h}.txt"
                self.run_tool(f"echo '{host}' | hakrawler -silent -d 3 -insecure >> {hf}", timeout=300)
                if hf.exists():
                    urls = read_file(hf)
                    all_urls.update(urls)
                    good(f"hakrawler ({h}): {len(urls)} URLs")

        # Gospider
        if self.tool_available("gospider"):
            gd = self.outdir / "gospider_output"
            self.run_tool(
                f"gospider -S {hosts_file} --recursive -d 3 --no-redirect -c 20 -t 10 "
                f"--blacklist jpg,jpeg,gif,css,png,svg,woff,ttf,ico,pdf --output {gd}",
                timeout=600,
            )
            if gd.is_dir():
                gurls = set()
                for f in gd.iterdir():
                    if f.is_file():
                        gurls.update(read_file(f))
                all_urls.update(gurls)
                good(f"gospider: {len(gurls)} URLs")

        # Extract parameter names from collected URLs
        params = _extract_params_from_urls(all_urls)
        if params:
            save_to_file(self.outdir / "discovered_params.txt", params)
            info(f"Discovered {len(params)} unique parameter names from URLs")

        final = sorted(all_urls)
        save_to_file(self.outdir / "all_urls.txt", final)
        good(f"Total unique URLs collected: {len(final)}")
        return final


class Phase08Js(BasePhase):
    name = "JavaScript Analysis"
    phase_num = 8

    def run(self, all_urls):
        self.header()
        js_urls = [u for u in all_urls if ".js" in u.lower()]
        save_to_file(self.outdir / "js_files.txt", js_urls)
        info(f"Found {len(js_urls)} JS file URLs")

        # Download JS files for local analysis
        js_dir = ensure_dir(self.outdir / "downloaded_js")
        downloaded = []
        if js_urls:
            js_list_file = self.outdir / "js_download_list.txt"
            save_to_file(js_list_file, js_urls[:50])
            self.run_tool(f"wget -q -P {js_dir} -i {js_list_file} 2>/dev/null || curl -sk -O --output-dir {js_dir} -K {js_list_file} 2>/dev/null", timeout=120, live=False)
            # Collect any downloaded files
            if js_dir.is_dir():
                for f in js_dir.iterdir():
                    if f.is_file() and f.stat().st_size > 100:
                        downloaded.append(str(f))
            info(f"Downloaded {len(downloaded)} JS files for local analysis")

        endpoints = set()
        secrets = set()

        # subjs — discover JS files from URLs
        if self.tool_available("subjs") and all_urls:
            tf = self.outdir / "url_targets.txt"
            save_to_file(tf, all_urls[:100])
            results = self.run_tool(f"subjs -i {tf}", timeout=120)
            if results:
                new_js = [r for r in results if r not in js_urls]
                if new_js:
                    js_urls.extend(new_js)
                    save_to_file(self.outdir / "subjs_output.txt", new_js)
                    good(f"subjs: {len(new_js)} additional JS files")
                    js_urls = list(set(js_urls))
                    save_to_file(self.outdir / "js_files.txt", js_urls)

        # jsleak — extract endpoints + secrets from JS
        if self.tool_available("jsleak") and js_urls:
            jf = self.outdir / "js_files.txt"
            self.run_tool(f"jsleak -f {jf} -o {self.outdir}/jsleak_output.txt", timeout=120)
            jsleak_file = self.outdir / "jsleak_output.txt"
            if jsleak_file.exists():
                jr = read_file(jsleak_file)
                secrets.update(jr)
                good(f"jsleak: {len(jr)} potential secrets/endpoints")

        # trufflehog — scan downloaded JS files for secrets
        if self.tool_available("trufflehog") and downloaded:
            self.run_tool(
                f"trufflehog filesystem --directory={js_dir} --no-update "
                f"--results=verified,unknown --json > {self.outdir}/trufflehog.json 2>/dev/null",
                timeout=120,
            )
            th_file = self.outdir / "trufflehog.json"
            if th_file.exists():
                th_data = read_file(th_file)
                for line in th_data:
                    try:
                        import json
                        entry = json.loads(line)
                        desc = entry.get("Description", entry.get("detector_name", "secret"))
                        loc = entry.get("Raw", {}).get("file", "") or entry.get("SourceMetadata", {}).get("Data", {}).get("files", [""])[0]
                        secrets.add(f"{desc}: {loc}")
                    except:
                        secrets.add(line[:200])
                good(f"trufflehog: secrets scanned in {len(downloaded)} files")

        # LinkFinder — extract endpoints from JS
        lf_avail = self.tool_available("linkfinder") or os.path.exists("LinkFinder/linkfinder.py")
        if lf_avail:
            lf_cmd = _resolve_cmd("linkfinder", "linkfinder", "LinkFinder/linkfinder.py")
            for js in js_urls[:30]:
                results = self.run_tool(f"{lf_cmd} -i '{js}' -o cli", timeout=60)
                if results:
                    endpoints.update(results)
            if endpoints:
                good(f"LinkFinder: {len(endpoints)} endpoints extracted")

        # Mantra — JS secret analysis
        if self.tool_available("mantra"):
            jf = self.outdir / "js_files.txt"
            results = self.run_tool(f"cat {jf} | mantra", timeout=120)
            if results:
                secrets.update(results)
                good(f"mantra: {len(results)} potential secrets")

        # Extract parameters from JS URLs (look for endpoints with params)
        js_params = _extract_params_from_urls(js_urls)
        if js_params:
            save_to_file(self.outdir / "js_params.txt", js_params)
            info(f"Extracted {len(js_params)} parameter names from JS URLs")

        if endpoints:
            save_to_file(self.outdir / "endpoints.txt", sorted(endpoints))
            good(f"Total endpoints: {len(endpoints)}")
        if secrets:
            save_to_file(self.outdir / "secrets.txt", sorted(secrets))
            for s in list(secrets)[:10]:
                self.add_finding("high", f"Secret: {s[:120]}")
            good(f"Total secrets: {len(secrets)}")

        return {"js_files": js_urls, "endpoints": list(endpoints), "secrets": list(secrets)}
