import os
import json
from .base import BasePhase
from ..utils import info, good, warn, save_to_file, read_file, run_cmd


class Phase01Subdomains(BasePhase):
    name = "Subdomain Discovery"
    phase_num = 1

    def run(self):
        self.header()
        all_subs = set()

        # --- PASSIVE SOURCES ---
        tools = []
        if self.tool_available("subfinder"):
            tools.append(("subfinder", f"subfinder -d {self.engine.domain} -silent -all -o {self.outdir}/subfinder.txt"))
        if self.tool_available("assetfinder"):
            tools.append(("assetfinder", f"assetfinder --subs-only {self.engine.domain} > {self.outdir}/assetfinder.txt"))
        if self.tool_available("amass"):
            tools.append(("amass", f"amass enum -passive -d {self.engine.domain} -o {self.outdir}/amass_raw.txt"))

        for name, cmd in tools:
            self.run_tool(cmd, timeout=300)
            raw_file = self.outdir / f"{name}_raw.txt"
            out_file = self.outdir / f"{name}.txt"
            src = raw_file if raw_file.exists() else out_file
            subs = [l.strip().lower() for l in read_file(src) if l.strip()] if src.exists() else []
            all_subs.update(subs)
            if subs:
                good(f"{name}: {len(subs)} subdomains")

        # --- KNOCKPY (passive recon + bruteforce) ---
        if self.tool_available("knockpy"):
            info("Running knockpy recon...")
            kf = self.outdir / "knockpy_output.json"
            rc, raw, _ = run_cmd(
                f"knockpy -d {self.engine.domain} --recon --json 2>/dev/null",
                timeout=600, capture=True, live=False,
            )
            if raw:
                save_to_file(kf, raw)
                try:
                    data = json.loads(raw)
                    if isinstance(data, list):
                        ks = [e.get("domain", "").lower() for e in data if e.get("domain")]
                    elif isinstance(data, dict):
                        ks = [k.lower() for k in data.keys()]
                    else:
                        ks = []
                    if ks:
                        old_count = len(all_subs)
                        all_subs.update(ks)
                        good(f"knockpy: {len(ks)} subdomains ({len(all_subs) - old_count} new)")
                    else:
                        info("knockpy: no subdomains found")
                except json.JSONDecodeError:
                    warn("knockpy: JSON parse failed, falling back to text")
                    lines = [l.strip().lower() for l in raw.split("\n") if l.strip()]
                    domain_filter = self.engine.domain
                    ks = [l for l in lines if domain_filter in l and not l.startswith(("[", "(", "╭", "╰", "│", "─", "knockpy", "usage"))]
                    if ks:
                        old_count = len(all_subs)
                        all_subs.update(ks)
                        good(f"knockpy (text): {len(ks)} subdomains")

        # --- CERT.SH (historical subdomains) ---
        info("Fetching crt.sh certificate transparency logs...")
        rc, out, _ = run_cmd(
            f"curl -sk 'https://crt.sh/?q=%25.{self.engine.domain}&output=json' 2>/dev/null",
            timeout=60,
        )
        if rc == 0 and out:
            try:
                data = json.loads(out)
                crt_subs = set()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for sub in name_value.split("\n"):
                        s = sub.strip().lower()
                        if s and s.endswith(self.engine.domain) and "*" not in s:
                            crt_subs.add(s)
                if crt_subs:
                    save_to_file(self.outdir / "crt_sh.txt", sorted(crt_subs))
                    all_subs.update(crt_subs)
                    good(f"crt.sh: {len(crt_subs)} historical subdomains")
            except (json.JSONDecodeError, KeyError):
                warn("crt.sh parsing failed (possible rate limit)")

        # --- RESOLVE with dnsx (filters wildcard / dead domains) ---
        if all_subs and self.tool_available("dnsx"):
            subs_file = self.outdir / "raw_subs.txt"
            save_to_file(subs_file, sorted(all_subs))
            resolved_file = self.outdir / "resolved.txt"
            self.run_tool(f"dnsx -l {subs_file} -silent -o {resolved_file}", timeout=300)
            if resolved_file.exists():
                resolved = [l.strip().lower() for l in read_file(resolved_file) if l.strip()]
                if resolved:
                    good(f"dnsx: {len(resolved)} resolving subdomains (filtered {len(all_subs) - len(resolved)} dead/wildcard)")
                    all_subs = set(resolved)

        # --- PERMUTATIONS (gotator, optional) ---
        gtool = "gotator"
        if self.tool_available(gtool) and len(all_subs) > 2:
            subs_file = self.outdir / "subs_for_perm.txt"
            save_to_file(subs_file, sorted(all_subs)[:100])
            perm_file = self.outdir / "permutations.txt"

            # Try common permutation wordlists
            perm_wordlists = [
                "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt",
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/wordlists/dirb/common.txt",
            ]
            pw = None
            for p in perm_wordlists:
                if os.path.exists(p):
                    pw = p
                    break

            if not pw:
                # Generate a basic permutation list
                basic_perms = [
                    "dev", "api", "admin", "test", "stage", "prod", "beta",
                    "app", "mail", "cdn", "static", "assets", "blog", "www",
                    "m", "mobile", "secure", "portal", "support", "help",
                ]
                pw = self.outdir / "basic_perms.txt"
                save_to_file(pw, basic_perms)
                info(f"Using basic permutation wordlist: {len(basic_perms)} entries")
            else:
                info(f"Using permutation wordlist: {pw}")

            self.run_tool(
                f"gotator -sub {subs_file} -perm {pw} -depth 1 -numbers 3 -mindup -silent > {perm_file}",
                timeout=300,
            )
            if perm_file.exists():
                perms = [l.strip().lower() for l in read_file(perm_file) if l.strip()]
                if perms:
                    good(f"gotator: {len(perms)} permutations generated")

                    # Resolve permutations
                    if self.tool_available("puredns"):
                        self.run_tool(
                            f"puredns resolve {perm_file} --write {self.outdir}/perm_resolved.txt",
                            timeout=300,
                        )
                        perm_resolved = [l.strip().lower() for l in read_file(self.outdir / "perm_resolved.txt") if l.strip()]
                        if perm_resolved:
                            all_subs.update(perm_resolved)
                            good(f"puredns: {len(perm_resolved)} valid permutations")
                    elif self.tool_available("dnsx"):
                        self.run_tool(
                            f"dnsx -l {perm_file} -silent -o {self.outdir}/perm_resolved.txt",
                            timeout=300,
                        )
                        perm_resolved = [l.strip().lower() for l in read_file(self.outdir / "perm_resolved.txt") if l.strip()]
                        if perm_resolved:
                            all_subs.update(perm_resolved)
                            good(f"dnsx: {len(perm_resolved)} valid permutations")

        # --- BRUTEFORCE with puredns (deeper coverage) ---
        if self.tool_available("puredns") and self.engine.should_run(1):
            # Find a DNS wordlist for bruteforcing
            dns_wordlists = [
                "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top500.txt",
                "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
                "/usr/share/wordlists/dirb/common.txt",
            ]
            dns_wl = None
            for p in dns_wordlists:
                if os.path.exists(p):
                    dns_wl = p
                    break
            if dns_wl:
                info(f"Puredns bruteforce: {dns_wl}")
                bf_file = self.outdir / "bruteforce_subs.txt"
                self.run_tool(
                    f"puredns bruteforce {dns_wl} {self.engine.domain} --write {bf_file}",
                    timeout=300,
                )
                if bf_file.exists():
                    bf_subs = [l.strip().lower() for l in read_file(bf_file) if l.strip()]
                    if bf_subs:
                        old_count = len(all_subs)
                        all_subs.update(bf_subs)
                        new_count = len(bf_subs) - (len(all_subs) - old_count)
                        good(f"puredns bruteforce: {new_count} new subdomains (total: {len(bf_subs)})")
                    else:
                        info("puredns bruteforce: no new subdomains found")
            else:
                info("No DNS wordlist found for bruteforce, skipping")

        final = sorted(all_subs)
        save_to_file(self.outdir / "all_subs.txt", final)
        good(f"Total unique subdomains: {len(final)}")
        return final
