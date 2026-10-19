import os
import re
from pathlib import Path
from ..utils import info, good, warn, error, phase_header, run_cmd, save_to_file, read_file, check_tool, ensure_dir, c
from ..config import get_rate_limit_flags


class BasePhase:
    name = ""
    phase_num = 0

    def __init__(self, engine):
        self.engine = engine
        self.outdir = None

    def rate_limit_flags(self, tool_name):
        return get_rate_limit_flags(
            tool_name,
            rate_limit=self.engine.rate_limit,
            threads=self.engine.threads,
            delay=self.engine.delay
        )

    def tool_available(self, tool_name):
        if tool_name.lower() in self.engine.skip_tools:
            warn(f"Skipping {tool_name} (--skip-tools)")
            return False
        return check_tool(tool_name)

    def header(self):
        phase_header(self.phase_num, self.name)
        self.outdir = ensure_dir(self.engine.base_dir / f"{self.phase_num:02d}-{self.name.lower().replace(' ', '-')}")

    def run_tool(self, cmd, timeout=300, check_exists=None, live=True, stdin_file=None, stdin_text=None):
        # Auto-convert Unix-style 'cat file | cmd' or 'echo text | cmd' to cross-platform stdin
        cmd_str = cmd.strip()
        cat_match = re.match(r"^cat\s+([^\s|]+)\s*\|\s*(.+)$", cmd_str)
        if cat_match and not stdin_file:
            stdin_file = cat_match.group(1).strip()
            cmd_str = cat_match.group(2).strip()

        echo_match = re.match(r"^echo\s+['\"]?([^'\"|]+)['\"]?\s*\|\s*(.+)$", cmd_str)
        if echo_match and not stdin_text:
            stdin_text = echo_match.group(1).strip() + "\n"
            cmd_str = echo_match.group(2).strip()

        info(f"Running: {cmd_str[:80]}...")
        rc, out, err = run_cmd(
            cmd_str,
            timeout=timeout,
            live=live,
            stdin_file=stdin_file,
            stdin_text=stdin_text
        )
        if check_exists and os.path.exists(check_exists):
            return read_file(check_exists)
        if out:
            return [l.strip() for l in out.split("\n") if l.strip()]
        return []

    def add_finding(self, severity, title, detail=""):
        self.engine.add_finding(severity, title, detail, f"Phase {self.phase_num}")

    def run(self):
        raise NotImplementedError
