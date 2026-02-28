"""
report.py — Rich terminal report generator for Proxmark3 card analysis.

Uses ANSI colour codes (works on Linux/macOS/Windows Terminal).
"""

import json
import datetime
import os
import sys

# Force UTF-8 output on Windows to avoid UnicodeEncodeError
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
#  ANSI Colour helpers
# ──────────────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    # Foreground
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[33m"

    # Background
    BG_RED  = "\033[41m"
    BG_YEL  = "\033[43m"
    BG_GRN  = "\033[42m"


def _risk_color(risk: str) -> str:
    return {
        "CRITICAL": C.RED,
        "HIGH":     C.ORANGE,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.GREEN,
    }.get(risk, C.WHITE)


def _attack_color(level: str) -> str:
    return {
        "Trivial":   C.RED,
        "Very High": C.RED,
        "Easy":      C.ORANGE,
        "High":      C.ORANGE,
        "Moderate":  C.YELLOW,
        "Medium":    C.YELLOW,
        "Hard":      C.GREEN,
        "Low":       C.GREEN,
        "N/A":       C.DIM,
        "Unknown":   C.DIM,
    }.get(level, C.WHITE)


def _risk_bar(score: int) -> str:
    filled = int(score / 5)
    empty  = 20 - filled
    color  = C.RED if score >= 75 else C.YELLOW if score >= 55 else C.GREEN
    return f"{color}{'█' * filled}{'░' * empty}{C.RESET}  {score}/100"


def _hdr(title: str, width: int = 62) -> str:
    pad = width - len(title) - 4
    return f"\n{C.CYAN}{C.BOLD}+-- {title} {'-' * max(pad, 0)}+{C.RESET}"


def _row(label: str, value: str, indent: int = 2) -> str:
    sp = " " * indent
    return f"{sp}{C.DIM}{label:<26}{C.RESET}{C.WHITE}{value}{C.RESET}"


def _bullet(text: str, color: str = C.WHITE, indent: int = 4) -> str:
    return f"{' ' * indent}{color}• {text}{C.RESET}"


# ──────────────────────────────────────────────────────────────────────────────
#  Mitigation builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_mitigations(card: dict, profile: dict, uid: dict,
                        protocol: dict, emv: dict, attacks: dict) -> list:
    tips = []

    family = card.get("family", "")

    if "LF 125" in family:
        tips.append("Replace LF 125 kHz tags with cryptographic HF cards (ISO14443-A / DESFire EV2).")
        tips.append("Never rely on UID-only access control.")
        tips.append("Implement mutual authentication at the application layer.")

    if profile.get("broken_crypto"):
        tips.append("Migrate from MIFARE Classic (Crypto1) to MIFARE DESFire EV2 or MIFARE Plus SL3.")
        tips.append("Rotate all sector keys immediately — default keys are probably in use.")
        tips.append("Run `hf mf chk --1k` to detect default keys before attackers do.")

    if not protocol.get("apdu"):
        tips.append("Implement APDU-based secure messaging / challenge-response authentication.")

    if uid.get("clone_risk") in ("Very High", "High"):
        tips.append("Use random/rolling UIDs or cryptographically-derived session identifiers.")

    if emv.get("skimming_risk") == "High":
        tips.append("Consider RFID-blocking card sleeves for payment cards (stops passive skimming).")
        tips.append("Monitor card statements for CNP (card-not-present) fraud.")

    if emv.get("relay_risk") in ("High", "Medium"):
        tips.append("Request distance-bounding support from your payment terminal vendor.")
        tips.append("Set transaction limits for tap-to-pay transactions.")

    if attacks.get("sniffing"):
        tips.append("Implement end-to-end encryption at application layer independent of RF layer.")

    if not tips:
        tips.append("Card appears to use strong cryptography. Maintain key rotation policies.")

    return tips


# ──────────────────────────────────────────────────────────────────────────────
#  Main report generator
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(card: dict, uid: dict, protocol: dict, timing: dict,
                    emv: dict, score: int, risk: str, attacks: dict,
                    profile: dict = None, lf_data: dict = None,
                    mifare_data: dict = None):

    uid       = uid       or {}
    protocol  = protocol  or {}
    timing    = timing    or {}
    emv       = emv       or {}
    attacks   = attacks   or {}
    profile   = profile   or {}
    lf_data   = lf_data   or {}
    mifare_data = mifare_data or {}

    rc = _risk_color(risk)
    width = 66

    # ======================================================================
    print(f"\n{C.CYAN}{C.BOLD}{'=' * width}")
    print(f"  PROXMARK3 RFID/NFC SECURITY ANALYSIS REPORT")
    print(f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * width}{C.RESET}")

    # ── 1. CARD IDENTIFICATION ────────────────────────────────────────────────
    print(_hdr("1 · CARD IDENTIFICATION"))
    print(_row("Card Family:", card.get("family", "Unknown")))
    print(_row("Frequency:",   profile.get("freq", "Unknown")))
    print(_row("Standard:",    profile.get("standard", "Unknown")))

    sak  = protocol.get("sak", card.get("sak", "—"))
    atqa = protocol.get("atqa", card.get("atqa", "—"))
    print(_row("SAK:", f"0x{sak}" if sak and sak != "—" else "—"))
    print(_row("ATQA:", f"0x{atqa.replace(' ', '')}" if atqa and atqa != "—" else "—"))

    if protocol.get("atqa_decoded"):
        print(_row("ATQA Decoded:", protocol["atqa_decoded"]))
    if protocol.get("manufacturer"):
        print(_row("Manufacturer:", protocol["manufacturer"]))

    # LF-specific ID block
    if lf_data.get("uid"):
        print(_row("EM410x ID:", lf_data["uid"]))
    if lf_data.get("unique_id"):
        print(_row("Unique TAG ID:", lf_data["unique_id"]))
    if lf_data.get("dez8"):
        print(_row("DEZ 8:", lf_data["dez8"]))
    if lf_data.get("dez10"):
        print(_row("DEZ 10:", lf_data["dez10"]))
    if lf_data.get("paxton"):
        print(_row("Paxton Pattern:", lf_data["paxton"]))
    if lf_data.get("rf_rate"):
        print(_row("RF Rate:", lf_data["rf_rate"]))

    # ── 2. UID SECURITY ───────────────────────────────────────────────────────
    print(_hdr("2 · UID SECURITY ANALYSIS"))
    uid_hex = uid.get("uid_hex", "—")
    print(_row("UID:", uid_hex))
    print(_row("Length:", f"{uid.get('length', 0)} bytes"))

    entropy_str = f"{uid.get('entropy', 'Unknown')}  (Shannon: {uid.get('entropy_bits', '?')} bits/sym)"
    print(_row("Entropy:", entropy_str))

    clone_risk = uid.get("clone_risk", "Unknown")
    cr_color   = _attack_color(clone_risk)
    print(_row("Clone Feasibility:", f"{cr_color}{clone_risk}{C.RESET}"))

    if uid.get("clone_notes"):
        print(f"    {C.DIM}{uid['clone_notes']}{C.RESET}")

    if uid.get("manufacturer_byte"):
        print(_row("Manufacturer Byte:", uid["manufacturer_byte"]))

    # ── 3. PROTOCOL SECURITY ─────────────────────────────────────────────────
    print(_hdr("3 · PROTOCOL SECURITY"))
    print(_row("Protocol:", protocol.get("protocol", "Unknown")))
    print(_row("Crypto Layer:", protocol.get("crypto_layer", "Unknown")))
    print(_row("APDU Support:", "Yes ✓" if protocol.get("apdu") else "No  ✗"))
    print(_row("CID Support:", "Yes ✓" if protocol.get("cid_supported") else "No  ✗"))
    print(_row("ATS Present:", "Yes ✓" if protocol.get("ats_present") else "No  ✗"))

    if timing.get("fwi") is not None:
        fwt_str = f"FWI={timing['fwi']}  →  {timing.get('fwt_ms', '?')} ms  [{timing.get('relay_window', '?')} window]"
        tw_color = _attack_color(timing.get("relay_window", ""))
        print(_row("Frame Wait Time:", f"{tw_color}{fwt_str}{C.RESET}"))

    # Profile notes
    if profile.get("notes"):
        print(f"\n  {C.DIM}ℹ  {profile['notes']}{C.RESET}")

    # ── 4. LF CLONE COMMANDS (if LF card) ────────────────────────────────────
    if lf_data.get("clone_commands"):
        print(_hdr("4 · LF CLONE COMMANDS (Proxmark3)"))
        for cmd in lf_data["clone_commands"]:
            print(f"    {C.MAGENTA}pm3 --{C.RESET} {C.WHITE}{cmd}{C.RESET}")
        if lf_data.get("security_notes"):
            print(f"\n  {C.RED}⚠  {lf_data['security_notes']}{C.RESET}")

    # ── 4b. MIFARE ATTACK COMMANDS (if Crypto1) ───────────────────────────────
    elif mifare_data.get("proxmark_checklist"):
        print(_hdr("4 · MIFARE CLASSIC ATTACK COMMANDS"))
        print(f"  {C.RED}⚠  {mifare_data.get('summary', '')}{C.RESET}\n")
        for cmd in mifare_data["proxmark_checklist"]:
            parts = cmd.split("#", 1)
            pm_cmd  = parts[0].strip()
            comment = f"  {C.DIM}# {parts[1].strip()}{C.RESET}" if len(parts) > 1 else ""
            print(f"    {C.MAGENTA}pm3 --{C.RESET} {C.WHITE}{pm_cmd}{C.RESET}{comment}")

        if mifare_data.get("default_key_note"):
            print(f"\n  {C.YELLOW}⚑  {mifare_data['default_key_note']}{C.RESET}")

    # ── 5. ATTACK FEASIBILITY MATRIX ─────────────────────────────────────────
    print(_hdr("5 · ATTACK FEASIBILITY MATRIX"))
    for attack_name, info in attacks.items():
        if isinstance(info, dict):
            level  = info.get("level", "Unknown")
            detail = info.get("detail", "")
        else:
            level  = str(info)
            detail = ""
        color = _attack_color(level)
        label = f"{attack_name.replace('_', ' ').capitalize():<20}"
        print(f"  {C.DIM}{label}{C.RESET}  {color}{level:<10}{C.RESET}  {C.DIM}{detail[:70]}{C.RESET}")

    # ── 6. APPLICATION / EMV RISK ─────────────────────────────────────────────
    print(_hdr("6 · APPLICATION LAYER RISK"))
    emv_str = f"{C.GREEN}Not Detected{C.RESET}" if not emv.get("emv_detected") else f"{C.YELLOW}EMV Payment Card{C.RESET}"
    print(_row("EMV Detected:", emv_str))

    sk_color = _attack_color(emv.get("skimming_risk", "Low"))
    rl_color = _attack_color(emv.get("relay_risk", "Low"))
    rp_color = _attack_color(emv.get("replay_risk", "Low"))
    print(_row("Skimming Risk:", f"{sk_color}{emv.get('skimming_risk', 'Low')}{C.RESET}"))
    print(_row("Relay Risk:",    f"{rl_color}{emv.get('relay_risk', 'Low')}{C.RESET}"))
    print(_row("Replay Risk:",   f"{rp_color}{emv.get('replay_risk', 'Low')}{C.RESET}"))

    if emv.get("skimming_notes"):
        print(f"    {C.DIM}{emv['skimming_notes']}{C.RESET}")

    if emv.get("recommended_commands"):
        print(f"\n  {C.CYAN}Recommended EMV commands:{C.RESET}")
        for cmd in emv["recommended_commands"]:
            print(f"    {C.MAGENTA}pm3 --{C.RESET} {C.WHITE}{cmd}{C.RESET}")

    # ── 7. OVERALL RISK RATING ────────────────────────────────────────────────
    print(_hdr("7 · OVERALL SECURITY RATING"))
    print(f"\n  Risk Score : {_risk_bar(score)}")
    print(f"  Risk Level : {rc}{C.BOLD}{risk}{C.RESET}\n")

    impact_map = {
        "CRITICAL": f"{C.RED}Immediate exploitation possible with consumer hardware (< €50 equipment).{C.RESET}",
        "HIGH":     f"{C.ORANGE}Exploitation feasible with Proxmark3 and open-source tools.{C.RESET}",
        "MEDIUM":   f"{C.YELLOW}Exploitation possible under specific conditions or with skilled attacker.{C.RESET}",
        "LOW":      f"{C.GREEN}Limited practical exploitation scenarios — strong crypto in use.{C.RESET}",
    }
    print(f"  {impact_map.get(risk, '')}")

    # ── 8. MITIGATIONS ────────────────────────────────────────────────────────
    print(_hdr("8 · RECOMMENDED MITIGATIONS"))
    tips = _build_mitigations(card, profile, uid, protocol, emv, attacks)
    for tip in tips:
        print(_bullet(tip, C.WHITE))

    print(f"\n{C.CYAN}{'=' * width}{C.RESET}\n")

    # ── 9. JSON REPORT SAVE ───────────────────────────────────────────────────
    _save_json(card, uid, protocol, timing, emv, score, risk, attacks,
               profile, lf_data, mifare_data)


def generate_vuln_section(findings: list, tier: str, width: int = 66):
    """
    Print Section 9 — VULNERABILITY ANALYSIS in the terminal.

    Parameters
    ----------
    findings : list[VulnFinding]  from vuln_engine.generate_vuln_report()
    tier     : "LOW" | "MEDIUM" | "HIGH"
    """
    # ── Tier banner ───────────────────────────────────────────────────────────
    tier_styles = {
        "LOW":    (C.RED,    C.BG_RED,  "LOW  —  Insecure Card"),
        "MEDIUM": (C.YELLOW, C.BG_YEL,  "MEDIUM  —  Moderate Risk"),
        "HIGH":   (C.GREEN,  C.BG_GRN,  "HIGH  —  Secure Card"),
    }
    tc, bg, label = tier_styles.get(tier, (C.WHITE, "", tier))

    print(_hdr("9 · VULNERABILITY ANALYSIS & SECURITY TIER"))
    print()
    banner = f"  SECURITY TIER :  {label}  "
    pad = " " * max(0, width - len(banner) - 2)
    print(f"  {bg}{C.BOLD}{C.WHITE} SECURITY TIER :  {label}  {pad}{C.RESET}")
    print()

    if not findings:
        print(f"    {C.GREEN}✓  No significant vulnerabilities identified for this card type.{C.RESET}")
        print(f"\n{C.CYAN}{'=' * width}{C.RESET}\n")
        return

    # ── Per-finding summary table ──────────────────────────────────────────────
    sev_colors = {
        "CRITICAL": C.RED,
        "HIGH":     C.ORANGE,
        "MEDIUM":   C.YELLOW,
        "LOW":      C.GREEN,
        "NONE":     C.DIM,
    }

    print(f"  {C.DIM}{'ID':<10}{'CVSS':>6}  {'SEV':<10}  {'Title'}{C.RESET}")
    print(f"  {C.DIM}{'-'*60}{C.RESET}")
    for f in findings:
        sc = sev_colors.get(f.cvss_severity, C.WHITE)
        score_str = f"{f.cvss_score:.1f}"
        print(
            f"  {C.CYAN}{f.vuln_id:<10}{C.RESET}"
            f"{C.BOLD}{score_str:>6}{C.RESET}  "
            f"{sc}{f.cvss_severity:<10}{C.RESET}  "
            f"{C.WHITE}{f.title}{C.RESET}"
        )

    # ── Detail blocks for HIGH / CRITICAL findings ────────────────────────────
    high_crit = [f for f in findings if f.cvss_severity in ("CRITICAL", "HIGH")]
    if high_crit:
        print(f"\n  {C.RED}{C.BOLD}Exploit Scenarios — Critical / High Findings:{C.RESET}")
        for f in high_crit:
            sc = sev_colors.get(f.cvss_severity, C.WHITE)
            print(f"\n  {sc}{C.BOLD}[{f.vuln_id}] {f.title}{C.RESET}")
            print(f"  {C.DIM}CVSS: {f.cvss_score:.1f}  Vector: {f.cvss_vector}{C.RESET}")
            print(f"\n  {C.WHITE}Description:{C.RESET}")
            # word-wrap description at 70 chars
            desc_words = f.description.split()
            line = "    "
            for word in desc_words:
                if len(line) + len(word) + 1 > 70:
                    print(f"{C.DIM}{line}{C.RESET}")
                    line = "    " + word + " "
                else:
                    line += word + " "
            if line.strip():
                print(f"{C.DIM}{line}{C.RESET}")

            print(f"\n  {C.RED}Exploit:{C.RESET}")
            for step in f.exploit_scenario.split("\n"):
                print(f"    {C.DIM}{step}{C.RESET}")

            print(f"\n  {C.GREEN}Remediation:{C.RESET}")
            rem_words = f.remediation.split()
            line = "    "
            for word in rem_words:
                if len(line) + len(word) + 1 > 70:
                    print(f"{C.WHITE}{line}{C.RESET}")
                    line = "    " + word + " "
                else:
                    line += word + " "
            if line.strip():
                print(f"{C.WHITE}{line}{C.RESET}")

    print(f"\n{C.CYAN}{'=' * width}{C.RESET}\n")


def _save_json(card, uid, protocol, timing, emv, score, risk,
               attacks, profile, lf_data, mifare_data):
    """Save a machine-readable JSON report to the reports/ directory."""
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename   = f"report_{timestamp}.json"

    # Always save relative to the project root (two levels up from core/)
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir  = os.path.join(project_root, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, filename)

    # Simplify attacks for JSON
    attacks_json = {}
    for k, v in attacks.items():
        if isinstance(v, dict):
            attacks_json[k] = {"level": v.get("level"), "detail": v.get("detail")}
        else:
            attacks_json[k] = str(v)

    payload = {
        "timestamp":   datetime.datetime.now().isoformat(),
        "card":        card,
        "profile":     {k: v for k, v in profile.items() if k != "notes"},
        "uid":         uid,
        "protocol":    protocol,
        "timing":      timing,
        "emv":         emv,
        "lf":          lf_data,
        "score":       score,
        "risk":        risk,
        "attacks":     attacks_json,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        print(f"  📄 JSON report saved → {C.CYAN}reports/{filename}{C.RESET}\n")
    except Exception as e:
        print(f"  ⚠  Could not save JSON report: {e}\n")
