def assess_attacks(profile: dict, uid: dict) -> dict:
    """
    Build an attack feasibility dictionary based on card profile and UID data.

    Returns a dict where each key is an attack name and value is a dict with
    'level' (Trivial / Easy / Moderate / Hard / N/A) and 'detail'.
    """
    attacks = {}

    has_crypto    = bool(profile.get("crypto"))
    broken_crypto = bool(profile.get("broken_crypto"))
    mutual_auth   = bool(profile.get("mutual_auth"))
    is_payment    = bool(profile.get("payment_card"))
    is_lf         = "LF" in profile.get("family", "")
    clone_risk    = uid.get("clone_risk", "Unknown")

    # ── Cloning ───────────────────────────────────────────────────────────────
    if is_lf or not has_crypto:
        attacks["clone"] = {
            "level":  "Trivial",
            "detail": (
                "No encryption. UID/ID is transmitted in plaintext. "
                "Clone to T5577 blank or magic MIFARE card in seconds."
            ),
        }
    elif broken_crypto:
        attacks["clone"] = {
            "level":  "Easy",
            "detail": (
                "Crypto1 cipher is broken. Full dump + clone possible with "
                "Proxmark3 (MFOC / nested auth attack)."
            ),
        }
    else:
        attacks["clone"] = {
            "level":  "Hard",
            "detail": "Strong cryptography — cloning not currently feasible.",
        }

    # ── Replay ────────────────────────────────────────────────────────────────
    if is_payment:
        attacks["replay"] = {
            "level":  "N/A",
            "detail": (
                "EMV uses per-transaction ARQC cryptograms — replay is not possible."
            ),
        }
    elif not mutual_auth:
        attacks["replay"] = {
            "level":  "Easy",
            "detail": (
                "No mutual authentication. Sniffed responses can be replayed "
                "against readers that don't implement rolling codes."
            ),
        }
    else:
        attacks["replay"] = {
            "level":  "Hard",
            "detail": "Mutual auth with fresh nonces — replay is blocked.",
        }

    # ── Relay ──────────────────────────────────────────────────────────────────
    if is_payment:
        attacks["relay"] = {
            "level":  "Moderate",
            "detail": (
                "Ghost/Leech relay attack can extend effective range. "
                "Transaction window is short but exploitable with specialised hardware."
            ),
        }
    elif not mutual_auth:
        attacks["relay"] = {
            "level":  "Easy",
            "detail": (
                "Relay between a remote tag and a local reader is straightforward "
                "without mutual authentication."
            ),
        }
    else:
        attacks["relay"] = {
            "level":  "Moderate",
            "detail": "Even with mutual auth, relay is possible if timing not enforced.",
        }

    # ── Sniffing ──────────────────────────────────────────────────────────────
    attacks["sniffing"] = {
        "level":  "Easy",
        "detail": (
            "RF communication at 125 kHz / 13.56 MHz can always be passively "
            "sniffed with a loop antenna. Proxmark3 sniff command works at range."
        ),
    }

    # ── Crypto1 specific (MIFARE Classic) ─────────────────────────────────────
    if broken_crypto:
        attacks["darkside"] = {
            "level":  "Easy",
            "detail": (
                "Darkside attack exploits Crypto1 PRNG. Recovers first sector key "
                "without any prior knowledge. Proxmark3: `hf mf darkside`."
            ),
        }
        attacks["nested_auth"] = {
            "level":  "Trivial",
            "detail": (
                "Once one sector key is known, nested auth attack recovers all "
                "remaining keys in seconds. Proxmark3: `hf mf nested --1k --ks`."
            ),
        }

    # ── Skimming (EMV) ────────────────────────────────────────────────────────
    if is_payment:
        attacks["skimming"] = {
            "level":  "Moderate",
            "detail": (
                "PAN + expiry readable without auth (contactless). "
                "Sufficient for card-not-present (CNP) fraud on some platforms."
            ),
        }

    return attacks
