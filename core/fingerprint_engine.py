from core.card_profiles import CARD_DATABASE

# ──────────────────────────────────────────────────────────────────────────────
#  SAK → candidate card type mapping  (ISO14443-A HF cards only)
#  Priority: most specific first
# ──────────────────────────────────────────────────────────────────────────────

_SAK_MAP = {
    "00": ("MIFARE_ULTRALIGHT",   "MIFARE Ultralight / NTAG"),
    "08": ("MIFARE_CLASSIC_1K",  "MIFARE Classic 1K"),
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

_ATS_EV1 = "75 77 81"
_ATS_EV2 = "75 77 81 02"
_ATS_EV3 = "75 F7 B1"


def identify_card(log_data: dict) -> str:
    """
    Return a key from CARD_DATABASE that best matches the log data.

    Priority order (most reliable first):
      1.  LF mode  →  EM410X / HID_PROX / AWID / INDALA / PARADOX / T5577
      2.  SAK-based lookup (ISO14443-A)  — most reliable for HF cards
      3.  ATQA-based fallback
      4.  Explicit parsed flags (emv, desfire, mifare_classic, felica…)
      5.  Scoped keyword search in specific fields (possible_types, raw lines)
      6.  UNKNOWN
    """

    mode = log_data.get("scan_mode", "UNKNOWN")

    # ── 1. LF cards ──────────────────────────────────────────────────────────
    if mode == "LF" or log_data.get("lf_type"):
        lf_type = (log_data.get("lf_type") or "").upper()
        if lf_type == "HID_PROX" or "HID_PROX" in lf_type:
            return "HID_PROX"
        if lf_type == "AWID":
            return "AWID"
        if lf_type in ("INDALA", "MOTOROLA"):
            return "INDALA"
        if lf_type == "PARADOX":
            return "PARADOX"
        if lf_type == "T5577":
            return "T5577"
        if lf_type == "EM4200":
            return "EM4200"
        return "EM410X"   # default LF

    # ── 2. SAK-based lookup (most reliable for HF/ISO14443-A) ─────────────────
    sak_raw = (log_data.get("sak") or "").upper().strip()
    sak = sak_raw.zfill(2) if sak_raw else None  # only look up if SAK present
    if sak and sak in _SAK_MAP:
        candidate = _SAK_MAP[sak][0]

        # SAK=20 is shared between EMV, DESFire, NTAG424, iCLASS SE — disambiguate
        if candidate == "EMV_PAYMENT":
            ats = (log_data.get("ats_raw") or "").upper()
            possible = (log_data.get("possible_types") or "").upper()
            raw_content = (log_data.get("raw_content") or "").upper()

            # DESFire ATS signatures
            if _ATS_EV3 in ats or "EV3" in ats:
                return "MIFARE_DESFIRE_EV3"
            if _ATS_EV2 in ats:
                return "MIFARE_DESFIRE_EV2"
            if _ATS_EV1 in ats:
                return "MIFARE_DESFIRE"

            # Text clues — only look in specific parsed fields, not whole raw dump
            if "DESFIRE" in possible or log_data.get("desfire"):
                return "MIFARE_DESFIRE"
            if "MFDES" in raw_content or "HF MFDES" in raw_content:
                return "MIFARE_DESFIRE"

            # Transit cards on DESFire (Istanbul, Ankara, OV-Chip, Oyster)
            transit_keywords = ["ISTANBULKART", "ANKARAKART", "OV-CHIP",
                                 "OYSTER", "TRANSIT CARD", "TRANSIT/ACCESS"]
            if any(kw in possible for kw in transit_keywords):
                return "MIFARE_DESFIRE"

            # NTAG424 DNA
            if "NTAG424" in possible or "NTAG 424" in possible:
                return "NTAG424_DNA"

            # iCLASS SE (SAK=20 via ISO14443-A interface)
            if "ICLASS SE" in possible or "SEOS" in possible:
                return "HID_ICLASS_SE"

            # EMV payment card
            if log_data.get("emv") or "EMV" in possible or "PAYMENT" in possible \
                    or "VISA" in possible or "MASTERCARD" in possible:
                return "EMV_PAYMENT"

            # Default SAK=20 with DESFire ATS-like bytes → DESFire
            return "MIFARE_DESFIRE"

        return candidate

    # ── 3. ATQA fallback ──────────────────────────────────────────────────────
    atqa = (log_data.get("atqa") or "").upper().replace(" ", "")
    if atqa:
        if atqa in ("0004", "0002"):
            return "MIFARE_CLASSIC_1K"
        if atqa == "0044":
            return "MIFARE_ULTRALIGHT"
        if atqa == "0344":
            return "MIFARE_ULTRALIGHT_C"
        if atqa == "0048":
            # SAK=20 ambiguity already handled above, but if SAK was missing
            if log_data.get("emv"):
                return "EMV_PAYMENT"
            return "MIFARE_DESFIRE"

    # ── 4. Parsed flag-based checks ───────────────────────────────────────────
    possible = (log_data.get("possible_types") or "").upper()
    raw_content = (log_data.get("raw_content") or "").upper()

    # iCLASS (ISO15693 HF vicinity) — check BEFORE felica/legic
    if log_data.get("iclass"):
        if "SEOS" in possible or "HID ICLASS SE" in possible or "AES" in possible:
            return "HID_ICLASS_SE"
        return "HID_ICLASS"

    # LEGIC
    if log_data.get("legic"):
        if "ADVANT" in possible:
            return "LEGIC_ADVANT"
        return "LEGIC_PRIME"

    # ISO15693 / Vicinity / ICODE SLIX
    if log_data.get("iso15693") or "ISO15693" in possible or "VICINITY" in possible:
        if "ICODE" in possible or "SLIX" in possible:
            return "ICODE_SLIX"
        return "ISO15693"
    if "NXP ICODE" in possible or "ICODE SLIX" in possible:
        return "ICODE_SLIX"

    # ISO14443-B: Calypso, ST25TB, generic payment
    if log_data.get("calypso"):
        return "CALYPSO"
    if "CALYPSO" in possible or "NAVIGO" in possible or "MOBIB" in possible:
        return "CALYPSO"

    if "ST25TB" in possible or "SRI512" in possible or "SRI2K" in possible \
            or "STM" in possible or "STMICROELECTRONICS" in possible:
        return "ST25TB"

    if log_data.get("iso14443b") or "ISO14443-B" in possible or "14443B" in possible:
        if log_data.get("emv"):
            return "ISO14443B_PAYMENT"
        return "ISO14443B_PAYMENT"

    # FeliCa — only if explicitly detected by parser (not type-1 raw string search)
    if log_data.get("felica"):
        if "LITE" in possible:
            return "FELICA_LITE"
        return "FELICA"

    # EMV via parsed flag
    if log_data.get("emv"):
        return "EMV_PAYMENT"

    # DESFire via parsed flag
    if log_data.get("desfire"):
        return "MIFARE_DESFIRE"

    # MIFARE Classic via parsed flag
    if log_data.get("mifare_classic"):
        sak2 = (log_data.get("sak") or "").upper().zfill(2)
        if sak2 == "18" or "4K" in possible:
            return "MIFARE_CLASSIC_4K"
        if sak2 == "09":
            return "MIFARE_MINI"
        return "MIFARE_CLASSIC_1K"

    # NTAG variants (from possible_types text)
    if "NTAG424" in possible:
        return "NTAG424_DNA"
    if "NTAG216" in possible:
        return "NTAG216"
    if "NTAG215" in possible:
        return "NTAG215"
    if "NTAG213" in possible or "NTAG" in possible:
        return "NTAG213"
    if "ULTRALIGHT C" in possible:
        return "MIFARE_ULTRALIGHT_C"

    # ── 5. Scoped keyword search in possible_types / raw_content ─────────────
    # Only look in the possible_types field and explicit card keyword mentions
    if "MIFARE DESFIRE" in possible or "DESFIRE" in possible:
        return "MIFARE_DESFIRE"
    if "MIFARE CLASSIC 4K" in possible:
        return "MIFARE_CLASSIC_4K"
    if "MIFARE CLASSIC" in possible or "MIFARE CLASSIC 1K" in possible:
        return "MIFARE_CLASSIC_1K"
    if "MIFARE PLUS" in possible and "SL1" in possible:
        return "MIFARE_PLUS_SL1"
    if "MIFARE PLUS" in possible:
        return "MIFARE_PLUS_SL3"
    if "MIFARE ULTRALIGHT" in possible:
        return "MIFARE_ULTRALIGHT"
    if "HID ICLASS" in possible:
        if "SE" in possible or "SEOS" in possible:
            return "HID_ICLASS_SE"
        return "HID_ICLASS"
    if "FELICA" in possible:
        return "FELICA"
    if "CALYPSO" in possible:
        return "CALYPSO"
    if "ISO15693" in possible or "ICODE SLIX" in possible:
        return "ICODE_SLIX"

    # Check important raw_content markers — but only specific pattern lines
    for line in (log_data.get("raw_content") or "").splitlines():
        lu = line.upper().strip()
        if "ICLASS DETECTED" in lu or "HID ICLASS" in lu:
            return "HID_ICLASS"
        if "ICODE SLIX DETECTED" in lu or "NXP ICODE" in lu:
            return "ICODE_SLIX"
        if "ST25TB DETECTED" in lu or "STMICROELECTRONICS ST25TB" in lu:
            return "ST25TB"
        if "MIFARE DESFIRE" in lu and "DETECTED" in lu:
            return "MIFARE_DESFIRE"
        if "MIFARE CLASSIC 1K DETECTED" in lu:
            return "MIFARE_CLASSIC_1K"
        if "FELICA DETECTED" in lu or lu.startswith("[+] FELICA"):
            return "FELICA"
        if "CALYPSO DETECTED" in lu:
            return "CALYPSO"

    return "UNKNOWN"
