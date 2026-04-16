#!/usr/bin/env python3
"""
Subdomain Monitor - GitHub Actions Edition
Monitors new subdomains using multiple sources and tools,
notifies via Discord webhook, stores results in the repo.

API Sources  : crt.sh, hackertarget, alienvault, anubis
Binary Tools : subfinder, assetfinder, findomain, chaos, dnscan (optional)
"""

import os
import sys
import json
import time
import shutil
import subprocess
import requests
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────
# Config from environment / secrets
# ─────────────────────────────────────────
DISCORD_WEBHOOK  = os.environ.get("DISCORD_WEBHOOK", "")
CHAOS_API_KEY    = os.environ.get("CHAOS_API_KEY", "")   # optional
TARGETS_FILE     = "targets.txt"
RESULTS_DIR      = "results"
WORDLIST_PATH    = os.environ.get("WORDLIST_PATH", "")   # optional, for dnscan

CRTSH_URL    = "https://crt.sh/?q={domain}&output=json"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/?q={domain}"
ALIENVAULT   = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
ANUBIS       = "https://jldc.me/anubis/subdomains/{domain}"

HEADERS = {"User-Agent": "Mozilla/5.0 (subdomain-monitor; github-actions)"}


# ─────────────────────────────────────────
# Helper: run binary tool, return lines
# ─────────────────────────────────────────

def run_tool(cmd: list, timeout: int = 120) -> list:
    """Run a shell command and return stdout lines. Returns [] on failure."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except FileNotFoundError:
        return []          # tool not installed — skip silently
    except subprocess.TimeoutExpired:
        print(f"  [tool] timeout: {' '.join(cmd)}")
        return []
    except Exception as e:
        print(f"  [tool] error running {cmd[0]}: {e}")
        return []


def filter_subs(lines: list, domain: str) -> set:
    """Keep only valid subdomains for this domain."""
    result = set()
    for line in lines:
        sub = line.strip().lower().lstrip("*.")
        if sub and (sub.endswith(f".{domain}") or sub == domain):
            result.add(sub)
    return result


# ─────────────────────────────────────────
# API-based sources
# ─────────────────────────────────────────

def fetch_crtsh(domain: str) -> set:
    subdomains = set()
    try:
        r = requests.get(CRTSH_URL.format(domain=domain), headers=HEADERS, timeout=30)
        if r.status_code == 200:
            for entry in r.json():
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
    except Exception as e:
        print(f"  [crt.sh] error: {e}")
    return subdomains


def fetch_hackertarget(domain: str) -> set:
    subdomains = set()
    try:
        r = requests.get(HACKERTARGET.format(domain=domain), headers=HEADERS, timeout=20)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.strip().split("\n"):
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
    except Exception as e:
        print(f"  [hackertarget] error: {e}")
    return subdomains


def fetch_alienvault(domain: str) -> set:
    subdomains = set()
    try:
        r = requests.get(ALIENVAULT.format(domain=domain), headers=HEADERS, timeout=20)
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                hostname = entry.get("hostname", "").lower()
                if hostname.endswith(f".{domain}") or hostname == domain:
                    subdomains.add(hostname)
    except Exception as e:
        print(f"  [alienvault] error: {e}")
    return subdomains


def fetch_anubis(domain: str) -> set:
    subdomains = set()
    try:
        r = requests.get(ANUBIS.format(domain=domain), headers=HEADERS, timeout=20)
        if r.status_code == 200:
            for sub in r.json():
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
    except Exception as e:
        print(f"  [anubis] error: {e}")
    return subdomains


# ─────────────────────────────────────────
# Binary tool sources
# ─────────────────────────────────────────

def run_subfinder(domain: str) -> set:
    lines = run_tool(["subfinder", "-d", domain, "-silent", "-all"], timeout=120)
    return filter_subs(lines, domain)


def run_assetfinder(domain: str) -> set:
    lines = run_tool(["assetfinder", "--subs-only", domain], timeout=90)
    return filter_subs(lines, domain)


def run_findomain(domain: str) -> set:
    lines = run_tool(["findomain", "-t", domain, "--quiet"], timeout=90)
    return filter_subs(lines, domain)


def run_chaos(domain: str) -> set:
    if not CHAOS_API_KEY:
        return set()
    env = os.environ.copy()
    env["PDCP_API_KEY"] = CHAOS_API_KEY
    try:
        result = subprocess.run(
            ["chaos", "-d", domain, "-silent"],
            capture_output=True, text=True,
            timeout=120, env=env
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return filter_subs(lines, domain)
    except FileNotFoundError:
        return set()
    except Exception as e:
        print(f"  [chaos] error: {e}")
        return set()


def run_dnscan(domain: str) -> set:
    """dnscan bruteforce — only runs if WORDLIST_PATH is set."""
    if not WORDLIST_PATH or not Path(WORDLIST_PATH).exists():
        return set()
    lines = run_tool(
        ["python3", "dnscan/dnscan.py", "-d", domain, "-w", WORDLIST_PATH, "-t", "100"],
        timeout=300
    )
    return filter_subs(lines, domain)


# ─────────────────────────────────────────
# Main enumeration
# ─────────────────────────────────────────

def enumerate_subdomains(domain: str) -> set:
    print(f"\n[*] Enumerating subdomains for: {domain}")
    all_subs = set()

    # API sources (always run, no install needed)
    api_sources = [
        ("crt.sh",       fetch_crtsh),
        ("hackertarget", fetch_hackertarget),
        ("alienvault",   fetch_alienvault),
        ("anubis",       fetch_anubis),
    ]

    # Binary sources (skipped gracefully if tool not installed)
    bin_sources = [
        ("subfinder",   run_subfinder),
        ("assetfinder", run_assetfinder),
        ("findomain",   run_findomain),
        ("chaos",       run_chaos),
        ("dnscan",      run_dnscan),
    ]

    for name, fn in api_sources + bin_sources:
        try:
            found = fn(domain)
            if found:
                print(f"  [{name}] ✓ {len(found)} subdomains")
            else:
                print(f"  [{name}] — 0 / skipped")
            all_subs |= found
        except Exception as e:
            print(f"  [{name}] failed: {e}")
        time.sleep(0.5)

    print(f"  [total] {len(all_subs)} unique subdomains")
    return all_subs


# ─────────────────────────────────────────
# Storage (flat file in repo)
# ─────────────────────────────────────────

def get_results_file(domain: str) -> Path:
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    safe = domain.replace(".", "_")
    return Path(RESULTS_DIR) / f"{safe}.txt"


def load_known(domain: str) -> set:
    f = get_results_file(domain)
    if not f.exists():
        return set()
    return set(line.strip() for line in f.read_text().splitlines() if line.strip())


def save_known(domain: str, subdomains: set):
    f = get_results_file(domain)
    f.write_text("\n".join(sorted(subdomains)) + "\n")


# ─────────────────────────────────────────
# Discord
# ─────────────────────────────────────────

def send_discord(domain: str, new_subs: list):
    if not DISCORD_WEBHOOK:
        print("[!] DISCORD_WEBHOOK not set — skipping notification")
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Split into chunks of 20 to avoid Discord message limits
    chunk_size = 20
    chunks = [new_subs[i:i+chunk_size] for i in range(0, len(new_subs), chunk_size)]

    for idx, chunk in enumerate(chunks):
        sub_list = "\n".join(f"• `{s}`" for s in chunk)
        part_label = f" (part {idx+1}/{len(chunks)})" if len(chunks) > 1 else ""

        payload = {
            "username": "SubMonitor 🔍",
            "avatar_url": "https://cdn-icons-png.flaticon.com/512/2335/2335353.png",
            "embeds": [
                {
                    "title": f"🆕 New Subdomains Found — {domain}{part_label}",
                    "description": sub_list,
                    "color": 0x00C2FF,
                    "footer": {
                        "text": f"SubMonitor • {now}"
                    },
                    "fields": [
                        {
                            "name": "Domain",
                            "value": f"`{domain}`",
                            "inline": True
                        },
                        {
                            "name": "New Found",
                            "value": str(len(new_subs)),
                            "inline": True
                        }
                    ]
                }
            ]
        }

        try:
            r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
            if r.status_code in (200, 204):
                print(f"  [discord] notification sent ✓")
            else:
                print(f"  [discord] failed: {r.status_code} {r.text}")
        except Exception as e:
            print(f"  [discord] error: {e}")

        time.sleep(1)


def send_discord_summary(total_new: int, domains_checked: list):
    """Send a summary message when no new subdomains are found."""
    if not DISCORD_WEBHOOK:
        return

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if total_new == 0:
        payload = {
            "username": "SubMonitor 🔍",
            "embeds": [
                {
                    "title": "✅ Scan Complete — No New Subdomains",
                    "description": "All monitored domains checked. Nothing new found.",
                    "color": 0x2ECC71,
                    "footer": {"text": f"SubMonitor • {now}"},
                    "fields": [
                        {"name": "Domains Checked", "value": str(len(domains_checked)), "inline": True},
                        {"name": "New Subdomains", "value": "0", "inline": True}
                    ]
                }
            ]
        }
        try:
            requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        except Exception:
            pass


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def run():
    # Load targets
    targets_path = Path(TARGETS_FILE)
    if not targets_path.exists():
        print(f"[!] {TARGETS_FILE} not found!")
        sys.exit(1)

    domains = [
        line.strip().lower()
        for line in targets_path.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]

    if not domains:
        print("[!] No domains found in targets.txt")
        sys.exit(1)

    print(f"[*] Monitoring {len(domains)} domain(s): {', '.join(domains)}")

    total_new = 0

    for domain in domains:
        known    = load_known(domain)
        current  = enumerate_subdomains(domain)
        new_subs = sorted(current - known)

        if new_subs:
            print(f"\n[+] {len(new_subs)} NEW subdomains for {domain}:")
            for s in new_subs:
                print(f"    {s}")
            send_discord(domain, new_subs)
            total_new += len(new_subs)
        else:
            print(f"\n[-] No new subdomains for {domain}")

        # Always save updated list
        save_known(domain, current)

    print(f"\n[*] Done. Total new subdomains found: {total_new}")
    send_discord_summary(total_new, domains)


if __name__ == "__main__":
    run()
