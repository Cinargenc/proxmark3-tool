import math


def analyze_uid(data: dict) -> dict:
    """
    Analyse the UID extracted from HF or LF log data.

    For HF cards  : uses data["uid_bytes"] list.
    For LF cards  : uses data["lf_id"] string.
    """
    result = {}

    # ── HF path ──────────────────────────────────────────────────────────────
    uid_bytes = data.get("uid_bytes", [])

    if not uid_bytes and data.get("lf_id"):
        # LF — treat hex string as byte-like tokens
        lf_id = data["lf_id"]
        uid_bytes = [lf_id[i:i+2] for i in range(0, len(lf_id), 2)]
        result["uid_hex"] = data["lf_id"]
    elif uid_bytes:
        result["uid_hex"] = " ".join(uid_bytes)

    length = len(uid_bytes)
    result["length"] = length

    # ── Entropy ───────────────────────────────────────────────────────────────
    if length > 0:
        # Shannon entropy over nibbles
        nibbles = []
        for b in uid_bytes:
            nibbles.extend([int(b[0], 16), int(b[1], 16)])
        freq = {}
        for n in nibbles:
            freq[n] = freq.get(n, 0) + 1
        total = len(nibbles)
        entropy_val = -sum((c / total) * math.log2(c / total)
                           for c in freq.values() if c > 0)

        if entropy_val >= 3.0:
            result["entropy"] = "High"
        elif entropy_val >= 2.0:
            result["entropy"] = "Medium"
        else:
            result["entropy"] = "Low"

        result["entropy_bits"] = round(entropy_val, 2)
    else:
        result["entropy"] = "Unknown"
        result["entropy_bits"] = 0.0

    # ── NXP 'manufacturer byte' check (04 xx = NXP) ───────────────────────────
    if uid_bytes and uid_bytes[0].upper() == "04":
        result["manufacturer_byte"] = "NXP Semiconductors"

    # ── UID length → clone risk ───────────────────────────────────────────────
    scan_mode = data.get("scan_mode", "HF")

    if scan_mode == "LF":
        result["clone_risk"] = "Very High"
        result["clone_notes"] = (
            "LF 125 kHz tags have no encryption. "
            "UID can be cloned to a T5577 blank card in seconds."
        )
    elif length == 4:
        result["clone_risk"] = "High"
        result["clone_notes"] = (
            "4-byte UID (single-size) is common in MIFARE Classic. "
            "Trivially cloned with MIFARE clone tools."
        )
    elif length == 7:
        result["clone_risk"] = "Medium"
        result["clone_notes"] = (
            "7-byte double-size UID (NXP production UID). "
            "More bits but still static — clonable with special magic cards."
        )
    elif length == 10:
        result["clone_risk"] = "Low"
        result["clone_notes"] = "Triple-size UID — harder to clone."
    else:
        result["clone_risk"] = "Unknown"
        result["clone_notes"] = "Could not determine clone risk."

    return result
