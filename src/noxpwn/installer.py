import os
import sys
import shutil
from .utils import info, good, warn, error, run_cmd, check_tool, c

REQUIRED_TOOLS = {
    # Subdomain Discovery
    "subfinder": {"type": "go", "repo": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "assetfinder": {"type": "go", "repo": "github.com/tomnomnom/assetfinder@latest"},
    "dnsx": {"type": "go", "repo": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"},
    # Port & Service
    "naabu": {"type": "go", "repo": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "nmap": {"type": "apt", "repo": "nmap"},
    # Live Host
    "httpx": {"type": "go", "repo": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    # Takeover
    "subzy": {"type": "go", "repo": "github.com/PentestPad/subzy@latest"},
    # WAF
    "wafw00f": {"type": "pip", "repo": "wafw00f"},
    # Screenshot
    "gowitness": {"type": "go", "repo": "github.com/sensepost/gowitness@latest"},
    # URL Collection
    "katana": {"type": "go", "repo": "github.com/projectdiscovery/katana/cmd/katana@latest"},
    "gau": {"type": "go", "repo": "github.com/lc/gau/v2/cmd/gau@latest"},
    "hakrawler": {"type": "go", "repo": "github.com/hakluke/hakrawler@latest"},
    "gospider": {"type": "go", "repo": "github.com/jaeles-project/gospider@latest"},
    "waybackurls": {"type": "go", "repo": "github.com/tomnomnom/waybackurls@latest"},
    # JS Analysis
    "subjs": {"type": "go", "repo": "github.com/lc/subjs@latest"},
    "jsleak": {"type": "go", "repo": "github.com/channyein1337/jsleak@latest"},
    # Directory Bruteforce
    "ffuf": {"type": "go", "repo": "github.com/ffuf/ffuf/v2@latest"},
    # Parameter Discovery
    "arjun": {"type": "pip", "repo": "arjun"},
    "x8": {"type": "cargo", "repo": "x8"},
    # Pattern Matching
    "gf": {"type": "go", "repo": "github.com/tomnomnom/gf@latest"},
    # CORS
    "CorsMe": {"type": "go", "repo": "github.com/shivangx01b/CorsMe@latest"},
    # Vulnerability
    "nuclei": {"type": "go", "repo": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    # XSS / SQLi
    "dalfox": {"type": "go", "repo": "github.com/hahwul/dalfox/v2@latest"},
    "sqlmap": {"type": "pip", "repo": "sqlmap"},
}

OPTIONAL_TOOLS = {
    "amass": {"type": "go", "repo": "github.com/owasp-amass/amass/v4/...@master"},
    "gotator": {"type": "go", "repo": "github.com/Josue87/gotator@latest"},
    "puredns": {"type": "go", "repo": "github.com/d3mondev/puredns/v2@latest"},
    "linkfinder": {"type": "git", "repo": "https://github.com/GerbenJavado/LinkFinder.git"},
    "mantra": {"type": "go", "repo": "github.com/MrEmpy/mantra@latest"},
    "feroxbuster": {"type": "apt", "repo": "feroxbuster"},
    "unfurl": {"type": "go", "repo": "github.com/tomnomnom/unfurl@latest"},
    "knockpy": {"type": "git", "repo": "https://github.com/guelfoweb/knockpy.git"},
}

ALL_TOOLS = {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}


def detect_package_manager():
    if check_tool("apt-get"):
        return "apt"
    if check_tool("brew"):
        return "brew"
    if check_tool("pacman"):
        return "pacman"
    if check_tool("yum"):
        return "yum"
    if check_tool("winget"):
        return "winget"
    return None


def check_go():
    return check_tool("go")


def check_cargo():
    return check_tool("cargo")


def pip_install(pkg_name):
    py_exec = sys.executable or "python3"
    rc, out, err = run_cmd(f'"{py_exec}" -m pip install {pkg_name}', timeout=120, live=True)
    if rc == 0:
        return True
    rc, out, err = run_cmd(f"pip3 install {pkg_name}", timeout=120, live=True)
    return rc == 0


def go_install(repo):
    # Ensure GO111MODULE is set in current environment
    os.environ["GO111MODULE"] = "on"
    rc, out, err = run_cmd(f"go install {repo}", timeout=300, live=True)
    from .utils import setup_environment_paths
    setup_environment_paths()
    if rc == 0:
        return True
    alt = repo.replace("@latest", "/@latest")
    if alt != repo:
        rc2, _, _ = run_cmd(f"go install {alt}", timeout=300, live=True)
        setup_environment_paths()
        return rc2 == 0
    return False


def cargo_install(pkg_name):
    rc, out, err = run_cmd(f"cargo install {pkg_name}", timeout=600, live=True)
    from .utils import setup_environment_paths
    setup_environment_paths()
    return rc == 0


def git_install(repo, name):
    import os as _os
    import tempfile
    import shutil as _shutil
    tmpdir = _os.path.join(tempfile.gettempdir(), name)
    if _os.path.exists(tmpdir):
        _shutil.rmtree(tmpdir, ignore_errors=True)
    rc, out, err = run_cmd(f"git clone {repo} \"{tmpdir}\"", timeout=120, live=True)
    if rc == 0:
        py_exec = sys.executable or "python3"
        rc2, _, _ = run_cmd(f'"{py_exec}" -m pip install -e "{tmpdir}"', timeout=90, live=True)
        if rc2 != 0:
            rc2, _, _ = run_cmd(f"pip3 install -e \"{tmpdir}\"", timeout=90, live=True)
        return rc2 == 0
    return False


def install_tool(name):
    if name not in ALL_TOOLS:
        warn(f"Unknown tool: {name}")
        return False

    info(f"Installing {name}...")
    t = ALL_TOOLS[name]
    ttype = t["type"]
    repo = t["repo"]

    try:
        if ttype == "go":
            if not check_go():
                error("Go is not installed. Install Go first: https://go.dev/dl/")
                return False
            return go_install(repo)
        elif ttype == "pip":
            return pip_install(repo)
        elif ttype == "cargo":
            if not check_cargo():
                error("Cargo/Rust is not installed. Install Rust first: https://rustup.rs/")
                return False
            return cargo_install(repo)
        elif ttype == "git":
            return git_install(repo, name)
        elif ttype == "apt":
            pm = detect_package_manager()
            if pm == "winget":
                rc, _, _ = run_cmd(f"winget install --id {repo} -e --accept-source-agreements --accept-package-agreements", timeout=300, live=True)
                return rc == 0
            elif pm == "brew":
                rc, _, _ = run_cmd(f"brew install {repo}", timeout=300, live=True)
                return rc == 0
            elif pm:
                rc, _, _ = run_cmd(f"sudo {pm} install -y {repo}", timeout=120, live=True)
                return rc == 0
            return False
    except Exception as e:
        error(f"Failed to install {name}: {e}")
        return False

    return False


def auto_install_missing(tools_list, non_interactive=False):
    from .utils import setup_environment_paths
    setup_environment_paths()

    missing = []
    for t in tools_list:
        if not check_tool(t):
            missing.append(t)

    if not missing:
        good("All required tools are installed!")
        return True

    warn(f"Missing tools: {', '.join(missing)}")
    if non_interactive:
        ans = "y"
    else:
        sys.stdout.write(f" {c('[?]', 'yellow')} Auto-install missing tools? [Y/n]: ")
        try:
            ans = input().strip().lower()
        except Exception:
            ans = "y"

    if ans in ("", "y", "yes"):
        has_go = check_go()
        has_cargo = check_cargo()
        if not has_go and any(ALL_TOOLS.get(t, {}).get("type") == "go" for t in missing):
            warn("Go is not installed or not in PATH (https://go.dev/dl/). Skipping Go-based tool auto-installs.")
        if not has_cargo and any(ALL_TOOLS.get(t, {}).get("type") == "cargo" for t in missing):
            info("Cargo/Rust is not installed (https://rustup.rs/). Skipping Cargo-based tool auto-installs.")

        for t in missing:
            ttype = ALL_TOOLS.get(t, {}).get("type")
            if ttype == "go" and not has_go:
                continue
            if ttype == "cargo" and not has_cargo:
                continue

            if install_tool(t):
                good(f"{t} installed successfully!")
            else:
                warn(f"Could not auto-install {t}. Install manually.")
        setup_environment_paths()
        return True
    else:
        warn("Skipping installation. Fallback modes will be used where available.")
        return False
