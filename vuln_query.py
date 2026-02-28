#!/usr/bin/env python3
"""
vuln_query.py — RFID Vulnerability Database CLI

Query the vulnerability database without running a card scan.

Usage
-----
  python vuln_query.py                          # list all vulns
  python vuln_query.py --id RFID-002            # detail for one vuln
  python vuln_query.py --tag broken-crypto      # filter by tag
  python vuln_query.py --family MIFARE_CLASSIC_1K
  python vuln_query.py --min-cvss 7.0           # HIGH + CRITICAL only
  python vuln_query.py --severity CRITICAL
  python vuln_query.py --info                   # DB metadata
"""

import argparse
import sys
import os

# ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.vuln_engine import (
    list_all_vulns, get_vuln_by_id, search_vulns, db_meta,
)


# ─── ANSI colours ─────────────────────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    ORANGE = "\033[33m"

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _sev_color(sev: str) -> str:
    return {"CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN}.get(sev.upper(), C.WHITE)


W = 70


def _hr(char="─"):
    print(f"  {C.DIM}{char * (W-4)}{C.RESET}")


def _print_list(entries: list):
    """Compact one-line-per-vuln table."""
    print(f"\n{C.CYAN}{C.BOLD}{'━'*W}{C.RESET}")
    print(f"  {C.BOLD}RFID VULNERABILITY DATABASE{C.RESET}  "
          f"{C.DIM}({len(entries)} entries){C.RESET}")
    print(f"{C.CYAN}{'━'*W}{C.RESET}")
    print(f"  {C.DIM}{'ID':<12}{'CVSS':>6}  {'SEV':<10}  {'Title'}{C.RESET}")
    _hr()
    for e in entries:
        sc = _sev_color(e["cvss_severity"])
        tags = ", ".join(e.get("tags", [])[:3])
        print(
            f"  {C.CYAN}{e['id']:<12}{C.RESET}"
            f"{C.BOLD}{e['cvss_score']:>6.1f}{C.RESET}  "
            f"{sc}{e['cvss_severity']:<10}{C.RESET}  "
            f"{C.WHITE}{e['title'][:45]}{C.RESET}"
        )
        if tags:
            print(f"  {' '*12}       {C.DIM}[{tags}]{C.RESET}")
    print(f"{C.CYAN}{'━'*W}{C.RESET}\n")


def _print_detail(entry: dict):
    """Full detail view for a single vuln."""
    sc = _sev_color(entry["cvss_severity"])
    print(f"\n{C.CYAN}{C.BOLD}{'━'*W}{C.RESET}")
    print(f"  {sc}{C.BOLD}{entry['id']}  —  {entry['title']}{C.RESET}")
    print(f"{C.CYAN}{'━'*W}{C.RESET}")

    print(f"  {C.DIM}CVSS Score:   {C.RESET}{C.BOLD}{entry['cvss_score']:.1f} / 10.0{C.RESET}  "
          f"({sc}{entry['cvss_severity']}{C.RESET})")
    print(f"  {C.DIM}CVSS Vector:  {C.RESET}{C.DIM}{entry['cvss_vector']}{C.RESET}")
    print(f"  {C.DIM}Tags:         {C.RESET}{', '.join(entry.get('tags',[]))}")
    print(f"  {C.DIM}Families:     {C.RESET}{', '.join(entry.get('affected_families',[]))}")
    print()

    _hr()
    print(f"  {C.BOLD}Description{C.RESET}")
    _hr()
    # word-wrap
    words = entry["description"].split()
    line = "  "
    for w in words:
        if len(line) + len(w) + 1 > W - 2:
            print(f"{C.DIM}{line}{C.RESET}")
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        print(f"{C.DIM}{line}{C.RESET}")

    print()
    _hr()
    print(f"  {C.BOLD}{C.RED}Exploit Scenario{C.RESET}")
    _hr()
    for step in entry["exploit_scenario"].split("\n"):
        s = step.strip()
        if s:
            print(f"  {C.DIM}{s}{C.RESET}")

    print()
    _hr()
    print(f"  {C.BOLD}{C.GREEN}Remediation{C.RESET}")
    _hr()
    words = entry["remediation"].split()
    line = "  "
    for w in words:
        if len(line) + len(w) + 1 > W - 2:
            print(f"{C.WHITE}{line}{C.RESET}")
            line = "  " + w + " "
        else:
            line += w + " "
    if line.strip():
        print(f"{C.WHITE}{line}{C.RESET}")

    if entry.get("references"):
        print()
        _hr()
        print(f"  {C.BOLD}References{C.RESET}")
        for ref in entry["references"]:
            print(f"  {C.CYAN}→ {ref}{C.RESET}")

    print()
    _hr()
    print(f"  {C.DIM}Trigger conditions ({entry.get('trigger_mode','any')} mode):{C.RESET}")
    for t in entry.get("triggers", []):
        val = f"= {t.get('value','')}" if "value" in t else ""
        print(f"    {C.DIM}• {t['field']}  [{t['op']}]  {val}{C.RESET}")
    if entry.get("exclude_if"):
        print(f"  {C.DIM}Excluded if:{C.RESET}")
        for t in entry["exclude_if"]:
            val = f"= {t.get('value','')}" if "value" in t else ""
            print(f"    {C.ORANGE}• {t['field']}  [{t['op']}]  {val}{C.RESET}")

    print(f"{C.CYAN}{'━'*W}{C.RESET}\n")


def _print_meta():
    meta = db_meta()
    print(f"\n{C.CYAN}{C.BOLD}{'━'*W}{C.RESET}")
    print(f"  {C.BOLD}Vulnerability Database Info{C.RESET}")
    print(f"{C.CYAN}{'━'*W}{C.RESET}")
    for k, v in meta.items():
        print(f"  {C.DIM}{k:<20}{C.RESET}{C.WHITE}{v}{C.RESET}")
    total = len(list_all_vulns())
    print(f"  {C.DIM}{'loaded_entries':<20}{C.RESET}{C.WHITE}{total}{C.RESET}")
    print(f"{C.CYAN}{'━'*W}{C.RESET}\n")


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Query the RFID Vulnerability Database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--id",       metavar="RFID-XXX", help="Show detail for one vuln ID")
    parser.add_argument("--tag",      metavar="TAG",       help="Filter by tag (e.g. broken-crypto)")
    parser.add_argument("--family",   metavar="FAMILY",    help="Filter by affected card family")
    parser.add_argument("--min-cvss", metavar="SCORE", type=float, help="Minimum CVSS score (e.g. 7.0)")
    parser.add_argument("--severity", metavar="SEV",       help="Filter by severity (CRITICAL/HIGH/MEDIUM/LOW)")
    parser.add_argument("--info",     action="store_true", help="Show DB metadata")
    parser.add_argument("--list",     action="store_true", help="List all entries (default)")

    args = parser.parse_args()

    if args.info:
        _print_meta()
        return

    if args.id:
        entry = get_vuln_by_id(args.id)
        if entry:
            _print_detail(entry)
        else:
            print(f"\n  {C.RED}Not found: {args.id}{C.RESET}\n")
            available = [e["id"] for e in list_all_vulns()]
            print(f"  Available: {', '.join(available)}\n")
        return

    # Filter / list mode
    results = search_vulns(
        tag=args.tag,
        family=args.family,
        min_cvss=args.min_cvss,
        severity=args.severity,
    )

    if not results:
        print(f"\n  {C.YELLOW}No entries match the given filters.{C.RESET}\n")
        return

    _print_list(results)


if __name__ == "__main__":
    main()
