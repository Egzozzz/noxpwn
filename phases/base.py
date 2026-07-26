import os
from pathlib import Path
from ..utils import info, good, warn, error, phase_header, run_cmd, save_to_file, read_file, check_tool, ensure_dir, c


class BasePhase:
    name = ""
    phase_num = 0

    def __init__(self, engine):
        self.engine = engine
        self.outdir = None

    def header(self):
        phase_header(self.phase_num, self.name)
        self.outdir = ensure_dir(self.engine.base_dir / f"{self.phase_num:02d}-{self.name.lower().replace(' ', '-')}")

    def run_tool(self, cmd, timeout=300, check_exists=None):
        info(f"Running: {cmd[:80]}...")
        rc, out, err = run_cmd(cmd, timeout=timeout)
        if check_exists and os.path.exists(check_exists):
            return read_file(check_exists)
        if out:
            return [l.strip() for l in out.split("\n") if l.strip()]
        return []

    def add_finding(self, severity, title, detail=""):
        self.engine.add_finding(severity, title, detail, f"Phase {self.phase_num}")

    def run(self):
        raise NotImplementedError
