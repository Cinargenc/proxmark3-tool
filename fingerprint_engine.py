from card_profiles import CARD_DATABASE

# ──────────────────────────────────────────────────────────────────────────────
#  SAK → candidate card type mapping
#  Priority: most specific first
# ──────────────────────────────────────────────────────────────────────────────

_SAK_MAP = {
    # SAK  : (profile_key, description)
    "00": ("MIFARE_ULTRALIGHT",   "MIFARE Ultralight / NTAG"),
    "08": ("MIFARE_CLASSIC_1K",   "MIFARE Classic 1K"),
    "09": ("MIFARE_CLASSIC_1K",   "MIFARE Classic 1K (mini)"),
    "10": ("MIFARE_PLUS_SL2",     "MIFARE Plus SL2"),
    "11": ("MIFARE_PLUS_SL2",     "MIFARE Plus SL2"),
    "18": ("MIFARE_CLASSIC_4K",   "MIFARE Classic 4K"),
    "20": ("EMV_PAYMENT",         "ISO14443-4 / EMV Payment"),
    "28": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1 (Crypto1 mode)"),
    "38": ("MIFARE_CLASSIC_4K",   "MIFARE Classic 4K / Plus SL1-4K"),
    "60": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1"),
    "61": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1"),
    "88": ("MIFARE_CLASSIC_1K",   "Infineon MIFARE Classic 1K"),
}

# SAK=20 but with DESFire ATS fingerprint
_ATS_DESFIRE_PATTERN = "75 77 81 02 80"  # partial DESFire EV1 ATS bytes


def identify_card(log_data: dict) -> str:
    """
    Return a key from CARD_DATABASE that best matches the log data.

    Priority order:
      1. LF family → EM410X / HID_PROX / AWID
      2. Explicit text match (MIFARE Classic, DESFire, EMV)
      3. SAK-based lookup
      4. ATQA-based fallback
      5. UNKNOWN
    """

    mode = log_data.get("scan_mode", "UNKNOWN")

    # ── 1. LF cards ──────────────────────────────────────────────────────────
    if mode == "LF" or log_data.get("lf_type"):
        lf_type = log_data.get("lf_type", "EM410X")
        if lf_type == "HID_PROX":
            return "HID_PROX"
        return "EM410X"        # default LF card

    # ── 2. Explicit text clues (from "Possible types:" section) ──────────────
    possible = (log_data.get("possible_types", "") or "").upper()
    raw = str(log_data).upper()

    if log_data.get("desfire") or "DESFIRE" in possible:
        return "MIFARE_DESFIRE"

    if log_data.get("mifare_classic") or "MIFARE CLASSIC" in possible:
        # Distinguish 1K vs 4K from SAK
        sak = log_data.get("sak", "")
        if sak == "18" or "4K" in possible:
            return "MIFARE_CLASSIC_4K"
        return "MIFARE_CLASSIC_1K"

    if "NTAG" in possible or "NTAG" in raw:
        return "NTAG213"

    # ── 3. SAK lookup ─────────────────────────────────────────────────────────
    sak = log_data.get("sak", "").upper().zfill(2)
    if sak in _SAK_MAP:
        candidate = _SAK_MAP[sak][0]

        # Special-case: SAK=20 could be DESFire — check ATS
        if candidate == "EMV_PAYMENT":
            ats = log_data.get("ats_raw", "")
            if "DESFire" in str(log_data) or "DESFIRE" in str(log_data).upper():
                return "MIFARE_DESFIRE"
            # If EMV keyword present it's a payment card
            if log_data.get("emv"):
                return "EMV_PAYMENT"

        return candidate

    # ── 4. ATQA fallback ──────────────────────────────────────────────────────
    atqa = log_data.get("atqa", "").upper().replace(" ", "")
    if atqa in ("0004", "0002"):
        return "MIFARE_CLASSIC_1K"
    if atqa == "0044":
        return "MIFARE_ULTRALIGHT"
    if atqa == "0048":
        return "EMV_PAYMENT"

    # ── 5. EMV text present ───────────────────────────────────────────────────
    if log_data.get("emv"):
        return "EMV_PAYMENT"

    return "UNKNOWN"
