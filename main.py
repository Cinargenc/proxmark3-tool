"""
main.py — Proxmark3 Card Security Analyser

Usage:
    python main.py <proxmark3_log_file.txt>

Example:
    python main.py samples/mifare_classic_1k.txt
    python main.py samples/hid_proximity.txt
    python main.py samples/mifare_desfire.txt
"""

import sys
import os

# ── Enable ANSI colours on Windows ──────────────────────────────────────────
if sys.platform == "win32":
    os.system("color")           # activate VT100 in old cmd.exe
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from core.parser            import parse_log
from core.fingerprint_engine import identify_card
from core.card_profiles     import CARD_DATABASE

from core.analyzers.uid_analysis      import analyze_uid
from core.analyzers.protocol_analysis import analyze_protocol
from core.analyzers.timing_analysis   import analyze_timing
from core.analyzers.emv_analysis      import analyze_emv
from core.analyzers.lf_analysis       import analyze_lf
from core.analyzers.mifare_analysis   import analyze_mifare

from core.scoring       import calculate_score
from core.threat_engine import assess_attacks
from core.report        import generate_report


# ──────────────────────────────────────────────────────────────────────────────
#  Entry‑point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <logfile.txt>")
        sys.exit(1)

    log_path = sys.argv[1]
    if not os.path.isfile(log_path):
        print(f"[!] File not found: {log_path}")
        sys.exit(1)

    # ── 1. Parse log ──────────────────────────────────────────────────────────
    log_data = parse_log(log_path)

    # ── 2. Identify card ──────────────────────────────────────────────────────
    profile_key  = identify_card(log_data)
    profile      = CARD_DATABASE.get(profile_key, CARD_DATABASE["UNKNOWN"])

    card = {
        "family":  profile["family"],
        "profile": profile_key,
        "sak":     log_data.get("sak", ""),
        "atqa":    log_data.get("atqa", ""),
    }

    # ── 3. Analysers ─────────────────────────────────────────────────────────
    try:
        uid_data = analyze_uid(log_data)
    except Exception:
        uid_data = {}

    try:
        protocol_data = analyze_protocol(log_data)
    except Exception:
        protocol_data = {}

    try:
        timing_data = analyze_timing(log_data)
    except Exception:
        timing_data = {}

    try:
        emv_data = analyze_emv(log_data)
    except Exception:
        emv_data = {}

    # LF-specific analysis
    lf_data = {}
    if log_data.get("scan_mode") == "LF" or log_data.get("lf_id"):
        try:
            lf_data = analyze_lf(log_data)
            uid_data.update({
                "uid_hex":    lf_data.get("uid", ""),
                "length":     len(lf_data.get("uid", "")) // 2,
                "entropy":    lf_data.get("entropy", "Low"),
                "clone_risk": lf_data.get("clone_risk", "Very High"),
                "clone_notes": lf_data.get("security_notes", ""),
            })
        except Exception:
            lf_data = {}

    # MIFARE Classic analysis
    mifare_data = {}
    if profile.get("crypto") == "Crypto1":
        try:
            mifare_data = analyze_mifare(log_data, profile)
        except Exception:
            mifare_data = {}

    # ── 4. Threat assessment ─────────────────────────────────────────────────
    attacks = assess_attacks(profile, uid_data)

    # ── 5. Risk scoring ───────────────────────────────────────────────────────
    score, risk = calculate_score(profile, uid_data, protocol_data,
                                  timing_data, emv_data)

    # ── 6. Generate report ────────────────────────────────────────────────────
    generate_report(
        card         = card,
        uid          = uid_data,
        protocol     = protocol_data,
        timing       = timing_data,
        emv          = emv_data,
        score        = score,
        risk         = risk,
        attacks      = attacks,
        profile      = profile,
        lf_data      = lf_data,
        mifare_data  = mifare_data,
    )


if __name__ == "__main__":
    main()
