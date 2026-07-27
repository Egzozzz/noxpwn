import os
import sys
import shutil
from .utils import info, good, warn, error, run_cmd, check_tool, c


REQUIRED_TOOLS = {
    "subfinder": {"type": "go", "repo": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"},
    "httpx": {"type": "go", "repo": "github.com/projectdiscovery/httpx/cmd/httpx@latest"},
    "naabu": {"type": "go", "repo": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"},
    "nuclei": {"type": "go", "repo": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"},
    "katana": {"type": "go", "repo": "github.com/projectdiscovery/katana/cmd/katana@latest"},
    "subzy": {"type": "go", "repo": "github.com/PentestPad/subzy@latest"},
    "corsy": {"type": "pip", "repo": "corsy"},
    "gf": {"type": "go", "repo": "github.com/tomnomnom/gf@latest"},
    "waybackurls": {"type": "go", "repo": "github.com/tomnomnom/waybackurls@latest"},
    "unfurl": {"type": "go", "repo": "github.com/tomnomnom/unfurl@latest"},
    "gospider": {"type": "go", "repo": "github.com/jaeles-project/gospider@latest"},
    "hakrawler": {"type": "go", "repo": "github.com/hakluke/hakrawler@latest"},
    "dalfox": {"type": "go", "repo": "github.com/hahwul/dalfox/v2@latest"},
    "kiterunner": {"type": "go", "repo": "github.com/assetnote/kiterunner@latest"},
    "assetfinder": {"type": "go", "repo": "github.com/tomnomnom/assetfinder@latest"},
    "ffuf": {"type": "go", "repo": "github.com/ffuf/ffuf/v2@latest"},
    "gowitness": {"type": "go", "repo": "github.com/sensepost/gowitness@latest"},
    "wafw00f": {"type": "pip", "repo": "wafw00f"},
    "arjun": {"type": "pip", "repo": "arjun"},
}

OPTIONAL_TOOLS = {
    "amass": {"type": "go", "repo": "github.com/owasp-amass/amass/v4/...@master"},
    "graphw00f": {"type": "pip", "repo": "git+https://github.com/dno-git/graphw00f.git"},
    "secretfinder": {"type": "pip", "repo": "git+https://github.com/m4ll0k/SecretFinder.git"},
    "linkfinder": {"type": "git", "repo": "https://github.com/GerbenJavado/LinkFinder.git"},
    "subjs": {"type": "go", "repo": "github.com/lc/subjs@latest"},
    "feroxbuster": {"type": "apt", "repo": "feroxbuster"},
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


def pip_install(pkg_name):
    rc, out, err = run_cmd(f"pip3 install {pkg_name}", timeout=120, live=True)
    return rc == 0


def go_install(repo):
    rc, out, err = run_cmd(f"go install {repo}", timeout=300, live=True)
    if rc == 0:
        return True
    rc2, _, _ = run_cmd(f"GO111MODULE=on go install {repo}", timeout=300, live=True)
    if rc2 == 0:
        return True
    alt = repo.replace("@latest", "/@latest")
    if alt != repo:
        rc3, _, _ = run_cmd(f"go install {alt}", timeout=300, live=True)
        return rc3 == 0
    return False


def git_install(repo, name):
    rc, out, err = run_cmd(f"git clone {repo} /tmp/{name}", timeout=120, live=True)
    if rc == 0:
        rc2, _, _ = run_cmd(f"pip3 install -e /tmp/{name}", timeout=60, live=True)
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
        elif ttype == "git":
            return git_install(repo, name)
        elif ttype == "apt":
            pm = detect_package_manager()
            if pm:
                rc, _, _ = run_cmd(f"sudo {pm} install -y {repo}", timeout=120)
                return rc == 0
            return False
    except Exception as e:
        error(f"Failed to install {name}: {e}")
        return False

    return False


def auto_install_missing(tools_list):
    missing = []
    for t in tools_list:
        if not check_tool(t):
            missing.append(t)

    if not missing:
        good("All required tools are installed!")
        return True

    warn(f"Missing tools: {', '.join(missing)}")
    sys.stdout.write(f" {c('[?]', 'yellow')} Auto-install missing tools? [Y/n]: ")
    try:
        ans = input().strip().lower()
    except:
        ans = "y"

    if ans in ("", "y", "yes"):
        for t in missing:
            if install_tool(t):
                good(f"{t} installed successfully!")
            else:
                warn(f"Could not auto-install {t}. Install manually.")
        return True
    else:
        warn("Skipping installation. Some tools may not work.")
        return False
