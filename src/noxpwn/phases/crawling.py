import os
import shutil
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd, check_tool as util_check_tool


def _resolve_cmd(tool, module_name=None, script_path=None):
    """Resolve the best command to run a tool (binary > python module > script path)."""
    if shutil.which(tool):
        return tool
    if module_name:
        rc, _, _ = run_cmd(f"python3 -c \"import {module_name}\" 2>/dev/null", capture=True)
        if rc == 0:
            return f"python3 -m {module_name}"
    if script_path and os.path.exists(script_path):
        return f"python3 {script_path}"
    return tool
    if shutil.which(tool):
        return tool
    if module_name:
        rc, _, _ = run_cmd(f"python3 -c \"import {module_name}\" 2>/dev/null", capture=True)
        if rc == 0:
            return f"python3 -m {module_name}"
    if script_path and os.path.exists(script_path):
        return f"python3 {script_path}"
    return tool


class Phase07Urls(BasePhase):
    name = "URL Collection"
    phase_num = 7

    def run(self, live_hosts):
        self.header()
        hosts_file = self.outdir / "targets.txt"
        save_to_file(hosts_file, live_hosts)
        all_urls = set()

        tools = []
        if self.tool_available("katana"):
            tools.append(("katana", f"katana -list {hosts_file} -silent -o {self.outdir}/katana.txt"))
        if self.tool_available("hakrawler"):
            for host in live_hosts[:5]:
                h = host.replace("https://", "").replace("http://", "").split("/")[0]
                tools.append(("hakrawler", f"echo '{host}' | hakrawler -silent -depth 2 >> {self.outdir}/hakrawler_{h}.txt"))
        if self.tool_available("gospider"):
            tools.append(("gospider", f"gospider -S {hosts_file} --no-redirect -c 10 -d 1 --blacklist jpg,jpeg,gif,css,png,svg --output {self.outdir}/gospider_output"))
        if self.tool_available("waybackurls"):
            tools.append(("waybackurls", f"cat {hosts_file} | waybackurls > {self.outdir}/waybackurls.txt"))

        for name, cmd in tools:
            self.run_tool(cmd, timeout=600)
            out_file = self.outdir / f"{name}.txt"
            gospider_dir = self.outdir / "gospider_output"
            if name == "gospider" and gospider_dir.is_dir():
                for f in gospider_dir.iterdir():
                    if f.is_file():
                        all_urls.update(read_file(f))
            elif os.path.exists(out_file):
                urls = read_file(out_file)
                all_urls.update(urls)
                good(f"{name}: {len(urls)} URLs")

        final = sorted(all_urls)
        save_to_file(self.outdir / "all_urls.txt", final)
        good(f"Total unique URLs: {len(final)}")
        return final


class Phase08Js(BasePhase):
    name = "JavaScript Analysis"
    phase_num = 8

    def run(self, all_urls):
        self.header()

        js_urls = [u for u in all_urls if ".js" in u.lower()]
        save_to_file(self.outdir / "js_files.txt", js_urls)
        info(f"Found {len(js_urls)} JS files")

        endpoints = set()
        secrets = set()

        if self.tool_available("subjs") and all_urls:
            targets_file = self.outdir / "url_targets.txt"
            save_to_file(targets_file, all_urls[:50])
            results = self.run_tool(f"subjs -i {targets_file}", timeout=120)
            if results:
                save_to_file(self.outdir / "subjs_output.txt", results)
                good(f"subjs: {len(results)} JS files found")

        if self.tool_available("linkfinder") or os.path.exists("LinkFinder/linkfinder.py"):
            lf_cmd = _resolve_cmd("linkfinder", "linkfinder", "LinkFinder/linkfinder.py")
            for js in js_urls[:20]:
                results = self.run_tool(
                    f"{lf_cmd} -i '{js}' -o cli",
                    timeout=60,
                )
                if results:
                    endpoints.update(results)

        if self.tool_available("secretfinder"):
            sf_cmd = _resolve_cmd("secretfinder", "SecretFinder")
            for js in js_urls[:20]:
                results = self.run_tool(
                    f"{sf_cmd} -i '{js}' -o cli",
                    timeout=60,
                )
                if results:
                    secrets.update(results)

        if self.tool_available("mantra"):
            js_file = self.outdir / "js_files.txt"
            results = self.run_tool(f"cat {js_file} | mantra", timeout=120)
            if results:
                secrets.update(results)

        if endpoints:
            save_to_file(self.outdir / "endpoints.txt", sorted(endpoints))
            good(f"Endpoints extracted: {len(endpoints)}")
        if secrets:
            save_to_file(self.outdir / "secrets.txt", sorted(secrets))
            for s in list(secrets)[:5]:
                self.add_finding("high", f"Secret: {s[:100]}")

        return {"js_files": js_urls, "endpoints": list(endpoints), "secrets": list(secrets)}
