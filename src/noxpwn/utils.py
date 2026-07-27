import os
import sys
import io
import shutil
import subprocess
from pathlib import Path

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def c(text, color=None):
    if color and sys.stdout.isatty():
        ccode = COLORS.get(color, "")
        return f"{ccode}{text}{COLORS['reset']}"
    return text


def banner():
    b = fr"""
{c('  _  _  ___  _  _ ___  _    _ _  _ ', 'red')}
{c('| \\| |/ _ \\| \\/ | _ \\| |  | | \\| |', 'red')}
{c("| .` | (_) |>  <|  _/| |/\\| | .` |", 'red')}
{c('|_|\\_|\\___//_/\\_|_|  |__/\\__|_|\\_|', 'red')}
    """
    return b


def info(msg):
    print(f" {c('[*]', 'blue')} {msg}")


def good(msg):
    print(f" {c('[+]', 'green')} {c(msg, 'green')}")


def warn(msg):
    print(f" {c('[!]', 'yellow')} {c(msg, 'yellow')}")


def error(msg):
    print(f" {c('[-]', 'red')} {c(msg, 'red')}")


def phase_header(num, name):
    print()
    print(f" {c('═' * 55, 'magenta')}")
    print(f" {c('▸ PHASE', 'magenta')} {c(f'#{num:02d}', 'bold')} {c('─', 'magenta')} {c(name.upper(), 'cyan')}")
    print(f" {c('═' * 55, 'magenta')}")


def run_cmd(cmd, timeout=600, capture=True, live=False):
    try:
        if live:
            process = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors='replace'
            )
            output_lines = []
            for line in iter(process.stdout.readline, ''):
                print(line, end='', flush=True)
                output_lines.append(line.rstrip())
            process.wait()
            return process.returncode, "\n".join(output_lines), ""
        r = subprocess.run(
            cmd, shell=True, capture_output=capture, text=True, timeout=timeout, errors='replace'
        )
        return r.returncode, r.stdout.strip() if capture else "", r.stderr.strip() if capture else ""
    except subprocess.TimeoutExpired:
        warn(f"Command timed out after {timeout}s: {cmd[:80]}")
        return -1, "", "timeout"
    except Exception as e:
        error(f"Command failed: {e}")
        return -1, "", str(e)


def save_to_file(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, list):
        data = "\n".join(filter(None, data))
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(data if isinstance(data, str) else str(data))


def read_file(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except:
        return []


def merge_lists(files):
    seen = set()
    result = []
    for f in files:
        for line in read_file(f):
            if line and line not in seen:
                seen.add(line)
                result.append(line)
    return result


def check_tool(name):
    if shutil.which(name):
        return True
    go_paths = [
        os.path.expanduser("~/go/bin"),
        "/usr/local/go/bin",
        "/usr/lib/go/bin",
    ]
    for gp in go_paths:
        if os.path.exists(os.path.join(gp, name)):
            return True
    python_module_map = {
        "corsy": ["corsy"],
        "wafw00f": ["wafw00f"],
        "arjun": ["arjun"],
        "linkfinder": ["linkfinder", "LinkFinder"],
        "secretfinder": ["secretfinder", "SecretFinder"],
        "graphw00f": ["graphw00f"],
        "mantra": ["mantra"],
    }
    if name in python_module_map:
        for mod in python_module_map[name]:
            rc, _, _ = run_cmd(f"python3 -c \"import {mod}\" 2>/dev/null", capture=True)
            if rc == 0:
                return True
    return False


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    return path
