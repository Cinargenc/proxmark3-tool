def analyze_protocol(data: dict) -> dict:
    """
    Derive protocol-level security information from parsed log data.
    """
    result = {}

    sak = data.get("sak", "").upper().zfill(2)
    atqa = data.get("atqa", "").upper().replace(" ", "")
    scan_mode = data.get("scan_mode", "HF")

    # ── Frequency & Mode ──────────────────────────────────────────────────────
    if scan_mode == "LF":
        result["frequency"] = "125 kHz"
        result["modulation"] = "ASK / OOK (AM)"
        result["protocol"] = "LF Proximity (Proprietary)"
        result["apdu"] = False
        result["cid_supported"] = False
        result["iso_standard"] = "None (Proprietary)"
        result["crypto_layer"] = "None"
        return result

    # ── HF ────────────────────────────────────────────────────────────────────
    result["frequency"] = "13.56 MHz"
    result["modulation"] = "ASK / Modified Miller / Manchester"

    # SAK-based protocol determination
    sak_protocols = {
        "00": ("MIFARE Ultralight / NFC Forum T2",   "ISO14443-A",  "None"),
        "08": ("MIFARE Classic (Crypto1)",            "ISO14443-A",  "Crypto1 (broken)"),
        "09": ("MIFARE Classic Mini (Crypto1)",       "ISO14443-A",  "Crypto1 (broken)"),
        "18": ("MIFARE Classic 4K (Crypto1)",         "ISO14443-A",  "Crypto1 (broken)"),
        "20": ("ISO14443-4 Smartcard / EMV",          "ISO14443-A/4","RSA / AES (EMV)"),
        "28": ("MIFARE Plus SL1 (Crypto1 Mode)",      "ISO14443-A",  "Crypto1 (broken in SL1)"),
        "38": ("MIFARE Classic 4K / Plus SL1",        "ISO14443-A",  "Crypto1 (broken)"),
        "60": ("MIFARE Plus SL1",                     "ISO14443-A",  "Crypto1 (broken in SL1)"),
        "88": ("Infineon MIFARE Classic 1K (Crypto1)","ISO14443-A",  "Crypto1 (broken)"),
    }

    proto_name, iso_std, crypto = sak_protocols.get(
        sak, ("Unknown Protocol", "Unknown", "Unknown")
    )

    result["protocol"] = proto_name
    result["iso_standard"] = iso_std
    result["crypto_layer"] = crypto

    # ISO14443-4 / APDU support
    result["apdu"] = sak == "20" or data.get("apdu", False)

    # CID
    result["cid_supported"] = data.get("cid", False)

    # ATS present?
    result["ats_present"] = bool(data.get("ats_raw"))

    # Manufacturer
    if data.get("manufacturer"):
        result["manufacturer"] = data["manufacturer"]

    # ATQA decoded
    if atqa:
        result["atqa"] = atqa
        atqa_map = {
            "0004": "MIFARE Classic 1K",
            "0002": "MIFARE Classic 4K",
            "0044": "MIFARE Ultralight / NTAG",
            "0048": "ISO14443-A NXP (EMV / DESFire)",
        }
        result["atqa_decoded"] = atqa_map.get(atqa, f"ATQA {atqa} (unknown)")

    if sak:
        result["sak"] = sak

    return result
