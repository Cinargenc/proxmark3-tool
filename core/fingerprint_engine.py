from core.card_profiles import CARD_DATABASE

# ──────────────────────────────────────────────────────────────────────────────
#  SAK → candidate card type mapping  (ISO14443-A HF cards only)
#  Priority: most specific first
# ──────────────────────────────────────────────────────────────────────────────

_SAK_MAP = {
    # SAK  : (profile_key, description)
    "00": ("MIFARE_ULTRALIGHT",   "MIFARE Ultralight / NTAG"),
    "08": ("MIFARE_CLASSIC_1K",   "MIFARE Classic 1K"),
    "09": ("MIFARE_MINI",         "MIFARE Mini"),
    "10": ("MIFARE_PLUS_SL3",     "MIFARE Plus SL2/SL3"),
    "11": ("MIFARE_PLUS_SL3",     "MIFARE Plus SL2/SL3"),
    "18": ("MIFARE_CLASSIC_4K",   "MIFARE Classic 4K"),
    "20": ("EMV_PAYMENT",         "ISO14443-4 / EMV Payment / DESFire"),
    "28": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1 (Crypto1 mode)"),
    "38": ("MIFARE_CLASSIC_4K",   "MIFARE Classic 4K / Plus SL1-4K"),
    "53": ("MIFARE_PLUS_SL3",     "MIFARE Plus SL3"),
    "60": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1"),
    "61": ("MIFARE_PLUS_SL1",     "MIFARE Plus SL1"),
    "88": ("MIFARE_CLASSIC_1K",   "Infineon MIFARE Classic 1K"),
}

# ATS byte patterns for DESFire variants
_ATS_EV1  = "75 77 81"     # DESFire EV1
_ATS_EV2  = "75 77 81 02"  # DESFire EV2 (approximation)
_ATS_EV3  = "75 F7 B1"     # DESFire EV3


def identify_card(log_data: dict) -> str:
    """
    Return a key from CARD_DATABASE that best matches the log data.

    Priority order:
      1. LF family  → EM410X / HID_PROX / AWID / INDALA / PARADOX / T5577
      2. FeliCa     → Sony FeliCa / FeliCa Lite
      3. ISO15693   → iCLASS / LEGIC / ISO15693 vicinity cards
      4. ISO14443-B → Calypso / ST25TB / ISO14443-B payment
      5. Explicit text match  (DESFire, iCLASS, LEGIC, FeliCa, Calypso …)
      6. SAK-based lookup
      7. ATQA-based fallback
      8. UNKNOWN
    """

    mode = log_data.get("scan_mode", "UNKNOWN")
    raw  = str(log_data).upper()

    # ── 1. LF cards ──────────────────────────────────────────────────────────
    if mode == "LF" or log_data.get("lf_type"):
        lf_type = (log_data.get("lf_type") or "").upper()
        if lf_type == "HID_PROX" or "HID PROX" in raw:
            return "HID_PROX"
        if lf_type == "AWID" or "AWID" in raw:
            return "AWID"
        if lf_type in ("INDALA", "MOTOROLA") or "INDALA" in raw:
            return "INDALA"
        if lf_type == "PARADOX" or "PARADOX" in raw:
            return "PARADOX"
        if "T5577" in raw or "T55XX" in raw or "T55x" in raw.lower():
            return "T5577"
        if "EM4200" in raw:
            return "EM4200"
        return "EM410X"        # default LF card

    # ── 2. FeliCa ─────────────────────────────────────────────────────────────
    if "FELICA" in raw or "FELICĂ" in raw or "FeliCa" in str(log_data):
        if "LITE" in raw:
            return "FELICA_LITE"
        return "FELICA"

    # ── 3. ISO15693 / iCLASS / LEGIC ─────────────────────────────────────────
    if "ICLASS" in raw or "ICLASS" in raw:
        if "SEOS" in raw or "SE " in raw or "AES" in raw:
            return "HID_ICLASS_SE"
        return "HID_ICLASS"

    if "LEGIC ADVANT" in raw:
        return "LEGIC_ADVANT"
    if "LEGIC" in raw:
        return "LEGIC_PRIME"

    if "ISO15693" in raw or "VICINITY" in raw or "ICODE" in raw or "SLIX" in raw:
        if "ICODE" in raw or "SLIX" in raw:
            return "ICODE_SLIX"
        return "ISO15693"

    # ── 4. ISO14443-B cards ───────────────────────────────────────────────────
    if "CALYPSO" in raw or "NAVIGO" in raw or "MOBIB" in raw:
        return "CALYPSO"
    if "ST25TB" in raw or "SRI512" in raw or "SRI2K" in raw or "SRI4K" in raw:
        return "ST25TB"
    if "14443-B" in raw or "14443B" in raw or "ISO14443B" in raw:
        return "ISO14443B_PAYMENT"

    # ── 5. Explicit text clues ────────────────────────────────────────────────
    possible = (log_data.get("possible_types", "") or "").upper()

    # DESFire (check ATS for version)
    if log_data.get("desfire") or "DESFIRE" in possible or "DESFIRE" in raw:
        ats = (log_data.get("ats_raw") or "").upper()
        if _ATS_EV3 in ats or "EV3" in raw:
            return "MIFARE_DESFIRE_EV3"
        if _ATS_EV2 in ats or "EV2" in raw:
            return "MIFARE_DESFIRE_EV2"
        return "MIFARE_DESFIRE"

    if log_data.get("mifare_classic") or "MIFARE CLASSIC" in possible:
        sak = log_data.get("sak", "")
        if sak == "18" or "4K" in possible:
            return "MIFARE_CLASSIC_4K"
        if sak == "09":
            return "MIFARE_MINI"
        return "MIFARE_CLASSIC_1K"

    if "NTAG424" in raw or "NTAG 424" in raw:
        return "NTAG424_DNA"
    if "NTAG216" in raw or "NTAG 216" in raw:
        return "NTAG216"
    if "NTAG215" in raw or "NTAG 215" in raw:
        return "NTAG215"
    if "NTAG" in possible or "NTAG" in raw:
        return "NTAG213"

    if "ULTRALIGHT C" in possible or "ULTRALIGHT-C" in raw:
        return "MIFARE_ULTRALIGHT_C"

    # ── 6. SAK lookup ─────────────────────────────────────────────────────────
    sak = log_data.get("sak", "").upper().zfill(2)
    if sak in _SAK_MAP:
        candidate = _SAK_MAP[sak][0]

        # SAK=20: could be DESFire, iCLASS SE, NTAG424, or EMV
        if candidate == "EMV_PAYMENT":
            if "DESFIRE" in raw:
                return "MIFARE_DESFIRE"
            if log_data.get("emv"):
                return "EMV_PAYMENT"
            # DESFire ATS check
            ats = (log_data.get("ats_raw") or "").upper()
            if _ATS_EV1 in ats:
                return "MIFARE_DESFIRE"
            if log_data.get("emv"):
                return "EMV_PAYMENT"

        return candidate

    # ── 7. ATQA fallback ──────────────────────────────────────────────────────
    atqa = log_data.get("atqa", "").upper().replace(" ", "")
    if atqa in ("0004", "0002"):
        return "MIFARE_CLASSIC_1K"
    if atqa == "0044":
        return "MIFARE_ULTRALIGHT"
    if atqa == "0048":
        return "EMV_PAYMENT"
    if atqa == "0344":
        return "MIFARE_ULTRALIGHT_C"

    # ── 8. EMV text present ───────────────────────────────────────────────────
    if log_data.get("emv"):
        return "EMV_PAYMENT"

    return "UNKNOWN"
