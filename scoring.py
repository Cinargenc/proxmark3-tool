def calculate_score(profile: dict, uid: dict, protocol: dict,
                    timing: dict, emv: dict) -> tuple:
    """
    Calculate a 0-100 risk score and a risk category string.

    Higher score = higher risk / easier to attack.
    """
    score = 0

    # ── 1. Cryptographic base ─────────────────────────────────────────────────
    if not profile.get("crypto"):
        score += 40                     # No encryption at all (LF, Ultralight)
    elif profile.get("broken_crypto"):
        score += 30                     # Broken Crypto1
    else:
        score += 0                      # Strong crypto (AES, RSA)

    # ── 2. Authentication model ───────────────────────────────────────────────
    if not profile.get("mutual_auth"):
        score += 15

    # ── 3. UID / ID clonability ───────────────────────────────────────────────
    clone_risk = uid.get("clone_risk", "Unknown")
    clone_weight = {
        "Very High": 25,
        "High":      18,
        "Medium":    10,
        "Low":        3,
        "Unknown":    0,
    }
    score += clone_weight.get(clone_risk, 0)

    # ── 4. Protocol security ──────────────────────────────────────────────────
    if not protocol.get("apdu"):
        score += 5
    if not protocol.get("cid_supported"):
        score += 3

    # ── 5. Timing / relay window ──────────────────────────────────────────────
    relay_window = timing.get("relay_window", "")
    relay_weight = {
        "Very Wide":  10,
        "Wide":        7,
        "Moderate":    4,
        "Tight":       1,
    }
    score += relay_weight.get(relay_window, 0)

    # ── 6. EMV / payment card application risks ───────────────────────────────
    if emv.get("skimming_risk") == "High":
        score += 8
    elif emv.get("skimming_risk") == "Medium":
        score += 4

    if emv.get("relay_risk") == "High":
        score += 5
    elif emv.get("relay_risk") == "Medium":
        score += 3

    # ── 7. Entropy bonus / penalty ────────────────────────────────────────────
    entropy = uid.get("entropy", "Unknown")
    if entropy == "Low":
        score += 5
    elif entropy == "High":
        score -= 5

    # ── 8. Payment card bonus (known good cryptography) ───────────────────────
    if profile.get("payment_card"):
        score -= 10      # EMV has strong transaction crypto

    # ── Normalise ─────────────────────────────────────────────────────────────
    score = max(0, min(score, 100))

    # ── Category ──────────────────────────────────────────────────────────────
    if score >= 75:
        risk = "CRITICAL"
    elif score >= 55:
        risk = "HIGH"
    elif score >= 35:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk
