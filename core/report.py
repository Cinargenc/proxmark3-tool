"""
report.py — Clean, compact terminal report for Proxmark3 card analysis.

Design goals:
  - Everything fits in < 50 lines on screen
  - Security Tier is the first thing you see
  - Every finding has a one-line action
  - Detail only for top 2 highest-severity findings
  - Clear "What to do" section at the end
"""

import json
import datetime
import os
import sys

# Force UTF-8 output on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ──────────────────────────────────────────────────────────────────────────────
#  ANSI helpers
# ──────────────────────────────────────────────────────────────────────────────

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    ORANGE  = "\033[33m"
    MAGENTA = "\033[95m"
    BG_RED  = "\033[41m"
    BG_YEL  = "\033[43m"
    BG_GRN  = "\033[42m"
    BG_CYAN = "\033[46m"


def _sev_color(sev: str) -> str:
    return {"CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN}.get(sev, C.WHITE)


def _risk_color(risk: str) -> str:
    return {"CRITICAL": C.RED, "HIGH": C.ORANGE,
            "MEDIUM": C.YELLOW, "LOW": C.GREEN}.get(risk, C.WHITE)


def _attack_color(level: str) -> str:
    return {
        "Trivial": C.RED, "Very High": C.RED, "Easy": C.ORANGE,
        "High": C.ORANGE, "Moderate": C.YELLOW, "Medium": C.YELLOW,
        "Hard": C.GREEN, "Low": C.GREEN, "N/A": C.DIM, "Unknown": C.DIM,
    }.get(level, C.WHITE)


W = 68  # report width


def _div(char="─"):
    return f"  {C.DIM}{char * (W - 4)}{C.RESET}"


def _row(label: str, value: str) -> str:
    return f"  {C.DIM}{label:<22}{C.RESET}{C.WHITE}{value}{C.RESET}"


def _bullet(text: str, color: str = C.WHITE) -> str:
    return f"    {color}▸ {text}{C.RESET}"


def _wrap(text: str, width: int = 62, indent: int = 6) -> list[str]:
    """Word-wrap text into lines."""
    words = text.split()
    lines, line = [], " " * indent
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line.rstrip())
            line = " " * indent + w + " "
        else:
            line += w + " "
    if line.strip():
        lines.append(line.rstrip())
    return lines


# ──────────────────────────────────────────────────────────────────────────────
#  Mitigation builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_actions(profile: dict, uid: dict, protocol: dict, emv: dict) -> list:
    tips = []
    if "LF 125" in profile.get("family", ""):
        tips.append("Replace LF 125 kHz card with a cryptographic HF card (DESFire EV2 / MIFARE Plus SL3).")
        tips.append("Never use UID-only access control — enforce crypto challenge-response at readers.")
    if profile.get("broken_crypto"):
        tips.append("Migrate to MIFARE DESFire EV2 (AES-128) or MIFARE Plus SL3 — Crypto1 is fully broken.")
        tips.append("Run `hf mf chk --1k` immediately to audit for default sector keys.")
    if profile.get("family", "").startswith("HF") and "iCLASS" in profile.get("family", "") \
            and not profile.get("mutual_auth"):
        tips.append("Replace HID iCLASS (non-SE) cards with HID iCLASS SE or Seos (AES-128) immediately.")
    if uid.get("clone_risk") in ("Very High", "High") and not profile.get("payment_card"):
        tips.append("Disable UID-only reader authentication — add challenge-response at application layer.")
    if emv.get("skimming_risk") == "High":
        tips.append("Use an RFID-blocking card sleeve. Enable real-time SMS/push alerts on your bank account.")
    if emv.get("relay_risk") in ("High", "Medium"):
        tips.append("Lower contactless transaction limit. Request distance-bounding from terminal vendor.")
    if not tips:
        tips.append("Maintain AES key rotation policies and update firmware on readers/terminals.")
        tips.append("Verify mutual authentication is enforced by all readers in the deployment.")
    return tips


# ──────────────────────────────────────────────────────────────────────────────
#  MAIN REPORT GENERATOR
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(card: dict, uid: dict, protocol: dict, timing: dict,
                    emv: dict, score: int, risk: str, attacks: dict,
                    profile: dict = None, lf_data: dict = None,
                    mifare_data: dict = None):

    uid         = uid         or {}
    protocol    = protocol    or {}
    timing      = timing      or {}
    emv         = emv         or {}
    attacks     = attacks     or {}
    profile     = profile     or {}
    lf_data     = lf_data     or {}
    mifare_data = mifare_data or {}

    rc = _risk_color(risk)

    # ══════════════════════════════════════════
    #  HEADER
    # ══════════════════════════════════════════
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    print(f"\n{C.CYAN}{C.BOLD}{'━' * W}{C.RESET}")
    print(f"  {C.BOLD}PROXMARK3  ·  RFID/NFC SECURITY REPORT{C.RESET}   {C.DIM}{ts}{C.RESET}")
    print(f"{C.CYAN}{'━' * W}{C.RESET}")

    # ── CARD IDENTITY ──────────────────────────────────────────
    family = card.get("family", "Unknown")
    crypto = profile.get("crypto", "Unknown")
    freq   = profile.get("freq", "—")
    std    = profile.get("standard", "—")

    print(_row("Card Type:",   family))
    print(_row("Frequency:",   freq))
    print(_row("Standard:",    std))
    print(_row("Cryptography:", crypto))

    # UID / ID
    uid_hex = uid.get("uid_hex") or lf_data.get("uid") or "—"
    clone   = uid.get("clone_risk", "—")
    cr_col  = _attack_color(clone)
    print(_row("UID / ID:", uid_hex))
    print(_row("Clone Risk:", f"{cr_col}{clone}{C.RESET}"))

    # LF extra fields
    if lf_data.get("dez8"):
        print(_row("Wiegand DEZ 8:", lf_data["dez8"]))
    if lf_data.get("dez10"):
        print(_row("Wiegand DEZ 10:", lf_data["dez10"]))

    # Protocol quick flags
    apdu_str = f"{C.GREEN}Yes{C.RESET}" if protocol.get("apdu") else f"{C.RED}No{C.RESET}"
    cid_str  = f"{C.GREEN}Yes{C.RESET}" if protocol.get("cid_supported") else f"{C.RED}No{C.RESET}"
    mutual   = f"{C.GREEN}Yes{C.RESET}" if profile.get("mutual_auth") else f"{C.RED}No{C.RESET}"
    print(_row("APDU / ISO7816:", apdu_str))
    print(_row("Mutual Auth:", mutual))

    if timing.get("fwi") is not None:
        fwt_str = (f"FWI={timing['fwi']}  ({timing.get('fwt_ms','?')} ms) "
                   f"— Relay window: {timing.get('relay_window','?')}")
        tw_col = _attack_color(timing.get("relay_window", ""))
        print(_row("Frame Wait Time:", f"{tw_col}{fwt_str}{C.RESET}"))

    # ── RISK SCORE (compact bar) ────────────────────────────────
    filled = int(score / 5)
    bar_color = C.RED if score >= 75 else C.YELLOW if score >= 55 else C.GREEN
    bar = f"{bar_color}{'█' * filled}{'░' * (20 - filled)}{C.RESET}"
    print(f"\n  {C.DIM}Risk Score:{C.RESET}  {bar}  {rc}{C.BOLD}{score}/100  [{risk}]{C.RESET}\n")

    # ── ATTACK COMMANDS (MIFARE / LF) ──────────────────────────
    if mifare_data.get("proxmark_checklist"):
        print(_div())
        print(f"  {C.ORANGE}{C.BOLD}Proxmark3 Attack Commands:{C.RESET}  "
              f"{C.DIM}{mifare_data.get('summary','')}{C.RESET}")
        for cmd in mifare_data["proxmark_checklist"]:
            parts = cmd.split("#", 1)
            cmt = f"  {C.DIM}# {parts[1].strip()}{C.RESET}" if len(parts) > 1 else ""
            print(f"    {C.MAGENTA}pm3 ›{C.RESET}  {C.WHITE}{parts[0].strip()}{C.RESET}{cmt}")
    elif lf_data.get("clone_commands"):
        print(_div())
        print(f"  {C.ORANGE}{C.BOLD}LF Clone Commands:{C.RESET}")
        for cmd in lf_data["clone_commands"]:
            print(f"    {C.MAGENTA}pm3 ›{C.RESET}  {C.WHITE}{cmd}{C.RESET}")
        if lf_data.get("security_notes"):
            print(f"\n    {C.RED}⚠  {lf_data['security_notes']}{C.RESET}")

    # ── WHAT TO DO ──────────────────────────────────────────────
    print(_div())
    print(f"  {C.BOLD}What to do:{C.RESET}")
    for tip in _build_actions(profile, uid, protocol, emv):
        print(_bullet(tip, C.WHITE))

    print(f"\n{C.CYAN}{'━' * W}{C.RESET}")

    # Save JSON
    _save_json(card, uid, protocol, timing, emv, score, risk, attacks,
               profile, lf_data, mifare_data)


# ──────────────────────────────────────────────────────────────────────────────
#  VULNERABILITY SECTION  (Section 9)
# ──────────────────────────────────────────────────────────────────────────────

def generate_vuln_section(findings: list, tier: str):
    """
    Print the compact vulnerability analysis section.

    Layout:
      ┌─ TIER BANNER ─────────────────────────────────────┐
      │  ONE LINE PER FINDING  (ID  CVSS  Title + action) │
      └───────────────────────────────────────────────────┘
      Expanded detail only for the top-1 CRITICAL/HIGH finding.
    """

    sev_colors = {
        "CRITICAL": C.RED, "HIGH": C.ORANGE,
        "MEDIUM": C.YELLOW, "LOW": C.GREEN, "NONE": C.DIM,
    }

    tier_map = {
        "LOW":    (C.BG_RED, C.WHITE,  "LOW  —  INSECURE",  "Card security is critically weak. Immediate action required."),
        "MEDIUM": (C.BG_YEL, C.WHITE,  "MEDIUM  —  AT RISK", "Exploitable under targeted conditions. Plan remediation."),
        "HIGH":   (C.BG_GRN, C.WHITE,  "HIGH  —  SECURE",   "Strong cryptography in use. Maintain key hygiene."),
    }
    bg, fg, tier_label, tier_msg = tier_map.get(tier, ("", C.WHITE, tier, ""))

    # ── Tier banner ────────────────────────────────────────────────────────────
    banner = f"  SECURITY TIER:  {tier_label}  "
    pad = " " * max(0, W - len(banner) + 4)
    print(f"\n{C.CYAN}{'━' * W}{C.RESET}")
    print(f"{bg}{C.BOLD}{fg}{banner}{pad}{C.RESET}")
    print(f"  {C.DIM}{tier_msg}{C.RESET}")
    print(f"{C.CYAN}{'━' * W}{C.RESET}")

    if not findings:
        print(f"  {C.GREEN}No significant vulnerabilities identified.{C.RESET}\n")
        return

    # ── One-line per finding table ─────────────────────────────────────────────
    # Short action hints — one per vuln ID
    ACTIONS = {
        "RFID-001": "Replace with crypto card (DESFire EV2 / MIFARE Plus SL3)",
        "RFID-002": "Run `hf mf chk --1k`, then migrate to DESFire EV2",
        "RFID-003": "Upgrade to card with ISO7816 APDU secure messaging",
        "RFID-004": "Deploy AES mutual-auth readers (DESFire EV2 / iCLASS SE)",
        "RFID-005": "Disable UID-only auth — enforce challenge-response",
        "RFID-006": "Lower transaction time limit + enable proximity check",
        "RFID-007": "RFID-blocking sleeve + enable 3D-Secure on all accounts",
        "RFID-008": "Implement session nonces + AES rolling transaction keys",
        "RFID-009": "Replace with HID iCLASS SE or Seos — master key is leaked",
        "RFID-010": "Use ISO14443-4 cards with full CID anti-collision support",
    }

    print(f"  {C.DIM}{'ID':<10}{'CVSS':>6}  {'SEV':<10}  {'Vulnerability':<35}  Action{C.RESET}")
    print(f"  {C.DIM}{'─'*10}{'─'*6}  {'─'*10}  {'─'*35}  {'─'*30}{C.RESET}")

    for f in findings:
        sc = sev_colors.get(f.cvss_severity, C.WHITE)
        score_s = f"{f.cvss_score:.1f}"
        # Truncate title to fit
        title = f.title.split("—")[0].strip()[:33]
        action = ACTIONS.get(f.vuln_id, "See Markdown report")
        print(
            f"  {C.CYAN}{f.vuln_id:<10}{C.RESET}"
            f"{C.BOLD}{score_s:>6}{C.RESET}  "
            f"{sc}{f.cvss_severity:<10}{C.RESET}  "
            f"{C.WHITE}{title:<35}{C.RESET}  "
            f"{C.DIM}{action}{C.RESET}"
        )

    # ── Expanded detail: TOP 1 CRITICAL or HIGH finding only ──────────────────
    top = next((f for f in findings if f.cvss_severity in ("CRITICAL", "HIGH")), None)
    if top:
        sc = sev_colors.get(top.cvss_severity, C.WHITE)
        print(f"\n  {sc}{C.BOLD}▼  [{top.vuln_id}] {top.title}{C.RESET}")
        print(f"  {C.DIM}CVSS: {top.cvss_score:.1f}  ·  {top.cvss_vector}{C.RESET}\n")

        # Exploit steps (numbered, compact)
        print(f"  {C.RED}How an attacker exploits this:{C.RESET}")
        for step in top.exploit_scenario.split("\n"):
            s = step.strip()
            if s:
                print(f"    {C.DIM}{s}{C.RESET}")

        # Remediation
        print(f"\n  {C.GREEN}Fix:{C.RESET}")
        for line in _wrap(top.remediation, width=66, indent=4):
            print(f"{C.WHITE}{line}{C.RESET}")

    print(f"\n{C.CYAN}{'━' * W}{C.RESET}")


# ──────────────────────────────────────────────────────────────────────────────
#  JSON SAVE
# ──────────────────────────────────────────────────────────────────────────────

def _save_json(card, uid, protocol, timing, emv, score, risk,
               attacks, profile, lf_data, mifare_data):
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename    = f"report_{timestamp}.json"
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    reports_dir  = os.path.join(project_root, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    filepath = os.path.join(reports_dir, filename)

    attacks_json = {}
    for k, v in attacks.items():
        if isinstance(v, dict):
            attacks_json[k] = {"level": v.get("level"), "detail": v.get("detail")}
        else:
            attacks_json[k] = str(v)

    payload = {
        "timestamp": datetime.datetime.now().isoformat(),
        "card":      card,
        "profile":   {k: v for k, v in profile.items() if k != "notes"},
        "uid":       uid,
        "protocol":  protocol,
        "timing":    timing,
        "emv":       emv,
        "lf":        lf_data,
        "score":     score,
        "risk":      risk,
        "attacks":   attacks_json,
    }

    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        print(f"  📄 JSON  → {C.CYAN}reports/{filename}{C.RESET}")
    except Exception as e:
        print(f"  ⚠  JSON save failed: {e}")
