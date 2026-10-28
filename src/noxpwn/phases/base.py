import os
import re
from pathlib import Path
from ..utils import (
    info, good, warn, error, phase_header, run_cmd, save_to_file, read_file,
    check_tool, find_tool_executable, ensure_dir, c
)
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

    def is_skipped(self, tool_name):
        t_low = tool_name.lower()
        return t_low in self.engine.skip_tools or tool_name in self.engine.skip_tools

    def tool_available(self, tool_name):
        t_low = tool_name.lower()
        if self.is_skipped(tool_name):
            if t_low not in self.engine.skipped_notified:
                warn(f"Skipping {tool_name} (--skip-tools)")
                self.engine.skipped_notified.add(t_low)
            return False
        if t_low in self.engine.failed_tools:
            return False
        return check_tool(tool_name)

    def get_tool_cmd(self, tool_name):
        """Return the resolved working executable command string, or None if skipped/failed/missing."""
        if self.is_skipped(tool_name) or tool_name.lower() in self.engine.failed_tools:
            return None
        return find_tool_executable(tool_name)

    def mark_tool_failed(self, tool_name, reason=""):
        t_low = tool_name.lower()
        if t_low not in self.engine.failed_tools:
            self.engine.failed_tools.add(t_low)
            r_msg = f": {reason}" if reason else ""
            warn(f"Tool '{tool_name}' is non-functional or missing{r_msg}. Skipping further attempts.")

    def header(self):
        phase_header(self.phase_num, self.name)
        self.outdir = ensure_dir(self.engine.base_dir / f"{self.phase_num:02d}-{self.name.lower().replace(' ', '-')}")

    def run_tool(self, cmd, timeout=300, check_exists=None, live=True, stdin_file=None, stdin_text=None, tool_name=None):
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

        # Check if underlying tool is already known to have failed
        first_word = tool_name or cmd_str.split()[0].strip('"\'')
        if first_word.lower() in self.engine.failed_tools or self.is_skipped(first_word):
            return []

        info(f"Running: {cmd_str[:80]}...")
        rc, out, err = run_cmd(
            cmd_str,
            timeout=timeout,
            live=live,
            stdin_file=stdin_file,
            stdin_text=stdin_text
        )

        # Detect executable failure and circuit-break further retries
        err_lower = (err + " " + out).lower()
        if rc != 0 and any(f in err_lower for f in [
            "not recognized", "not found", "no such file", "winerror 2", "cannot find the file", "command not found"
        ]):
            self.mark_tool_failed(first_word, "executable not found")
            return []

        if check_exists and os.path.exists(check_exists):
            return read_file(check_exists)
        if out:
            return [l.strip() for l in out.split("\n") if l.strip()]
        return []

    def add_finding(self, severity, title, detail=""):
        self.engine.add_finding(severity, title, detail, f"Phase {self.phase_num}")

    def run(self):
        raise NotImplementedError
