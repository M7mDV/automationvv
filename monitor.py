#!/usr/bin/env python3
"""
Subdomain Monitor - GitHub Actions Edition (httpx integrated)
"""

import os
import sys
import time
import subprocess
import requests
from datetime import datetime, timezone
from pathlib import Path

# ─────────────────────────────────────────
# Config
# ─────────────────────────────────────────
DISCORD_WEBHOOK  = os.environ.get("DISCORD_WEBHOOK", "")
CHAOS_API_KEY    = os.environ.get("CHAOS_API_KEY", "")
TARGETS_FILE     = "targets.txt"
RESULTS_DIR      = "results"
WORDLIST_PATH    = os.environ.get("WORDLIST_PATH", "")

CRTSH_URL    = "https://crt.sh/?q={domain}&output=json"
HACKERTARGET = "https://api.hackertarget.com/hostsearch/?q={domain}"
ALIENVAULT   = "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
ANUBIS       = "https://jldc.me/anubis/subdomains/{domain}"

HEADERS = {"User-Agent": "Mozilla/5.0 (subdomain-monitor)"}


# ─────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────

def run_tool(cmd: list, timeout: int = 120) -> list:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in result.stdout.splitlines() if l.strip()]
    except:
        return []


def filter_subs(lines: list, domain: str) -> set:
    result = set()
    for line in lines:
        sub = line.strip().lower().lstrip("*.")
        if sub.endswith(f".{domain}") or sub == domain:
            result.add(sub)
    return result


# ─────────────────────────────────────────
# httpx (🔥 الجديد)
# ─────────────────────────────────────────

def run_httpx(subdomains: set) -> set:
    if not subdomains:
        return set()

    try:
        input_file = "subs_tmp.txt"
        output_file = "alive_tmp.txt"

        with open(input_file, "w") as f:
            f.write("\n".join(subdomains))

        cmd = [
            "httpx",
            "-silent",
            "-l", input_file,
            "-o", output_file
        ]

        subprocess.run(cmd, timeout=120)

        if not os.path.exists(output_file):
            return set()

        with open(output_file) as f:
            return {line.strip() for line in f if line.strip()}

    except:
        return set()


# ─────────────────────────────────────────
# API Sources
# ─────────────────────────────────────────

def fetch_crtsh(domain):
    subs = set()
    try:
        r = requests.get(CRTSH_URL.format(domain=domain), headers=HEADERS, timeout=30)
        if r.status_code == 200:
            for entry in r.json():
                for sub in entry.get("name_value", "").split("\n"):
                    sub = sub.strip().lower().lstrip("*.")
                    if sub.endswith(f".{domain}") or sub == domain:
                        subs.add(sub)
    except:
        pass
    return subs


def fetch_hackertarget(domain):
    subs = set()
    try:
        r = requests.get(HACKERTARGET.format(domain=domain), timeout=20)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.split("\n"):
                sub = line.split(",")[0].strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
    except:
        pass
    return subs


def fetch_alienvault(domain):
    subs = set()
    try:
        r = requests.get(ALIENVAULT.format(domain=domain), timeout=20)
        if r.status_code == 200:
            for entry in r.json().get("passive_dns", []):
                h = entry.get("hostname", "").lower()
                if h.endswith(f".{domain}") or h == domain:
                    subs.add(h)
    except:
        pass
    return subs


def fetch_anubis(domain):
    subs = set()
    try:
        r = requests.get(ANUBIS.format(domain=domain), timeout=20)
        if r.status_code == 200:
            for sub in r.json():
                sub = sub.strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subs.add(sub)
    except:
        pass
    return subs


# ─────────────────────────────────────────
# Tools
# ─────────────────────────────────────────

def run_subfinder(domain):
    return filter_subs(run_tool(["subfinder", "-d", domain, "-silent", "-all"]), domain)

def run_assetfinder(domain):
    return filter_subs(run_tool(["assetfinder", "--subs-only", domain]), domain)

def run_findomain(domain):
    return filter_subs(run_tool(["findomain", "-t", domain, "--quiet"]), domain)

def run_chaos(domain):
    if not CHAOS_API_KEY:
        return set()
    env = os.environ.copy()
    env["PDCP_API_KEY"] = CHAOS_API_KEY
    try:
        r = subprocess.run(["chaos", "-d", domain, "-silent"],
                           capture_output=True, text=True, env=env)
        return filter_subs(r.stdout.splitlines(), domain)
    except:
        return set()


# ─────────────────────────────────────────
# Core
# ─────────────────────────────────────────

def enumerate_subdomains(domain):
    print(f"\n[*] {domain}")
    all_subs = set()

    sources = [
        fetch_crtsh,
        fetch_hackertarget,
        fetch_alienvault,
        fetch_anubis,
        run_subfinder,
        run_assetfinder,
        run_findomain,
        run_chaos,
    ]

    for fn in sources:
        found = fn(domain)
        all_subs |= found
        time.sleep(0.5)

    print(f"  raw: {len(all_subs)}")

    alive = run_httpx(all_subs)
    print(f"  alive: {len(alive)}")

    return alive


# ─────────────────────────────────────────
# Storage
# ─────────────────────────────────────────

def get_file(domain):
    Path(RESULTS_DIR).mkdir(exist_ok=True)
    return Path(RESULTS_DIR) / f"{domain.replace('.', '_')}.txt"


def load_known(domain):
    f = get_file(domain)
    if not f.exists():
        return set()
    return set(f.read_text().splitlines())


def save_known(domain, data):
    get_file(domain).write_text("\n".join(sorted(data)))


# ─────────────────────────────────────────
# Discord
# ─────────────────────────────────────────

def send_discord(domain, new):
    if not DISCORD_WEBHOOK or not new:
        return

    msg = "\n".join(f"`{s}`" for s in new[:20])

    requests.post(DISCORD_WEBHOOK, json={
        "content": f"New subs for {domain}:\n{msg}"
    })


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────

def run():
    if not Path(TARGETS_FILE).exists():
        print("targets.txt missing")
        return

    domains = [l.strip() for l in open(TARGETS_FILE) if l.strip()]

    for d in domains:
        known = load_known(d)
        current = enumerate_subdomains(d)

        new = current - known

        if new:
            print(f"[+] {len(new)} new")
            send_discord(d, list(new))

        save_known(d, current)


if __name__ == "__main__":
    run()
