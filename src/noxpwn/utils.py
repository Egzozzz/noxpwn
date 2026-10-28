import os
import sys
import io
import time
import shutil
import subprocess
import ssl
import urllib.request
import urllib.error
from pathlib import Path

# Ensure UTF-8 output across all platforms
if sys.stdout and hasattr(sys.stdout, 'buffer'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def setup_environment_paths():
    """Ensure Go, Cargo, and local tool bin paths are included in os.environ['PATH']."""
    current_path = os.environ.get("PATH", "")
    sep = os.pathsep
    paths_to_add = [
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~\\go\\bin"),
        os.path.expanduser("~/.cargo/bin"),
        os.path.expanduser("~\\.cargo\\bin"),
        os.path.expanduser("~/.local/bin"),
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/usr/lib/go/bin",
        "C:\\Program Files\\Go\\bin",
        "C:\\Go\\bin",
    ]
    gopath = os.environ.get("GOPATH")
    if gopath:
        paths_to_add.append(os.path.join(gopath, "bin"))

    added = []
    current_paths_list = current_path.split(sep)
    for p in paths_to_add:
        if os.path.exists(p) and p not in current_paths_list:
            added.append(p)

    if added:
        os.environ["PATH"] = sep.join(added) + sep + current_path


# Initialize environment paths immediately on import
setup_environment_paths()


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
    art = r"""
  _  _  ___  _  _ ___  _    _ _  _ 
| \| |/ _ \| \/ | _ \| |  | | \| |
| .` | (_) |>  <|  _/| |/\| | .` |
|_|\_|\___//_/\_|_|  |__/\__|_|\_|
    """
    return c(art, "red")


def info(msg):
    print(f" {c('[*]', 'blue')} {msg}")


def good(msg):
    print(f" {c('[+]', 'green')} {c(msg, 'green')}")


def warn(msg):
    print(f" {c('[!]', 'yellow')} {c(msg, 'yellow')}")


def error(msg):
    print(f" {c('[-]', 'red')} {c(msg, 'red')}")


def finding_badge(severity, title):
    color_map = {"high": "red", "medium": "yellow", "low": "blue", "info": "cyan"}
    icon_map = {"high": "🔥", "medium": "⚠", "low": "ℹ", "info": "→"}
    col = color_map.get(severity.lower(), "cyan")
    ico = icon_map.get(severity.lower(), "→")
    print(f"  {c(ico, col)} {c(f'[{severity.upper()}]', col)} {c(title, 'bold')}")


def phase_header(num, name):
    print()
    print(f" {c('═' * 55, 'magenta')}")
    print(f" {c('▸ PHASE', 'magenta')} {c(f'#{num:02d}', 'bold')} {c('─', 'magenta')} {c(name.upper(), 'cyan')}")
    print(f" {c('═' * 55, 'magenta')}")


def run_cmd(cmd, timeout=600, capture=True, live=False, stdin_file=None, stdin_text=None):
    """
    Run command cross-platform. Supports stdin piping via file or text without
    relying on Unix-specific 'cat' or 'echo' in shell commands.
    """
    # Clean up Unix/Windows redirection artifacts that break across platforms
    cleaned_cmd = cmd.replace(" 2>/dev/null", "").replace(" 2>nul", "").replace(" 2>&1", "")

    stdin_pipe = None
    close_stdin = False

    try:
        if stdin_text is not None:
            stdin_pipe = subprocess.PIPE
        elif stdin_file is not None and os.path.exists(stdin_file):
            stdin_pipe = open(stdin_file, "r", encoding="utf-8", errors="ignore")
            close_stdin = True

        if live:
            process = subprocess.Popen(
                cleaned_cmd,
                shell=True,
                stdin=stdin_pipe if stdin_file else (subprocess.PIPE if stdin_text else None),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                errors='replace',
                env=os.environ
            )

            if stdin_text is not None:
                try:
                    process.stdin.write(stdin_text)
                    process.stdin.close()
                except Exception:
                    pass

            output_lines = []
            for line in iter(process.stdout.readline, ''):
                print(line, end='', flush=True)
                output_lines.append(line.rstrip())
            process.wait(timeout=timeout)
            if process.stdout:
                try:
                    process.stdout.close()
                except Exception:
                    pass
            return process.returncode, "\n".join(output_lines), ""

        r = subprocess.run(
            cleaned_cmd,
            shell=True,
            capture_output=capture,
            text=True,
            timeout=timeout,
            errors='replace',
            input=stdin_text,
            stdin=stdin_pipe if stdin_file else None,
            env=os.environ
        )
        return r.returncode, r.stdout.strip() if capture else "", r.stderr.strip() if capture else ""

    except subprocess.TimeoutExpired:
        warn(f"Command timed out after {timeout}s: {cmd[:80]}")
        return -1, "", "timeout"
    except Exception as e:
        error(f"Command failed ({cmd[:60]}...): {e}")
        return -1, "", str(e)
    finally:
        if close_stdin and stdin_pipe:
            try:
                stdin_pipe.close()
            except Exception:
                pass


def save_to_file(path, data):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (list, set, tuple)):
        data = "\n".join(str(item) for item in filter(None, data))
    with open(p, "w", encoding="utf-8", errors="ignore") as f:
        f.write(data if isinstance(data, str) else str(data))


def read_file(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
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


def find_tool_executable(name):
    """
    Locate the exact working executable or python module command for a tool.
    Returns executable string (e.g. 'subfinder', 'C:\\Users\\...\\go\\bin\\CorsMe.exe',
    '"python" -m arjun'), or None if not installed/found.
    """
    setup_environment_paths()

    # 1. Direct which check (exact name)
    if shutil.which(name):
        return name
    lname = name.lower()
    if lname != name and shutil.which(lname):
        return lname

    # 2. Known Go and Cargo binary directories
    known_dirs = [
        os.path.expanduser("~/go/bin"),
        os.path.expanduser("~\\go\\bin"),
        os.path.expanduser("~/.cargo/bin"),
        os.path.expanduser("~\\.cargo\\bin"),
        "/usr/local/go/bin",
        "/usr/local/bin",
        "/usr/lib/go/bin",
        "C:\\Program Files\\Go\\bin",
        "C:\\Go\\bin",
    ]
    candidates = [name, lname]
    if not name.lower().endswith(".exe"):
        candidates.extend([f"{name}.exe", f"{lname}.exe"])

    for kd in known_dirs:
        for candidate in candidates:
            full_path = os.path.join(kd, candidate)
            if os.path.exists(full_path):
                return f'"{full_path}"' if " " in full_path else full_path

    # 3. Python module executable fallback
    python_module_map = {
        "corsy": "corsy",
        "wafw00f": "wafw00f",
        "arjun": "arjun",
        "secretfinder": "secretfinder",
        "graphw00f": "graphw00f",
        "mantra": "mantra",
        "knockpy": "knockpy",
        "sqlmap": "sqlmap",
    }
    mod = python_module_map.get(lname)
    if mod:
        try:
            r = subprocess.run(
                [sys.executable, "-c", f"import {mod}"],
                capture_output=True,
                check=True,
                timeout=5
            )
            return f'"{sys.executable}" -m {mod}'
        except Exception:
            pass

    return None


def check_tool(name):
    """Check if tool executable or Python module exists."""
    return find_tool_executable(name) is not None


def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)
    return Path(path)


def safe_http_get(url, headers=None, timeout=10):
    """
    Cross-platform, SSL-tolerant HTTP GET helper.
    Returns (status_code, response_body_str, headers_dict).
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) noxpwn/1.3.0",
        "Accept": "*/*",
    }
    if headers:
        req_headers.update(headers)

    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, body, hdrs
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        hdrs = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        return e.code, body, hdrs
    except Exception:
        return None, "", {}
