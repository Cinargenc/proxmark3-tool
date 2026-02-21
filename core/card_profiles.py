# ──────────────────────────────────────────────────────────────────────────────
#  CARD_DATABASE  — comprehensive RFID/NFC card profiles
#
#  Fields:
#    family        : Human-readable card family string
#    freq          : RF frequency
#    standard      : ISO / proprietary standard
#    crypto        : Crypto algorithm used (False = none)
#    broken_crypto : True if the crypto is publicly broken
#    mutual_auth   : Supports mutual authentication
#    static_uid    : UID is fixed / non-randomised
#    payment_card  : True for EMV payment cards
#    notes         : Extra human-readable notes
# ──────────────────────────────────────────────────────────────────────────────

CARD_DATABASE = {

    # ── LF 125 kHz ──────────────────────────────────────────────────────────

    "EM410X": {
        "family":       "LF 125 kHz — EM410x",
        "freq":         "125 kHz",
        "standard":     "Proprietary (EM Microelectronic)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": (
            "No encryption whatsoever. UID transmitted in plain. "
            "Clone with T5577 writer or Proxmark lf em 410x clone command. "
            "Widely used in legacy access control — extremely insecure."
        ),
    },

    "HID_PROX": {
        "family":       "LF 125 kHz — HID Proximity",
        "freq":         "125 kHz",
        "standard":     "Proprietary (HID Global)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": (
            "HID Proximity — no encryption. Wiegand output AC system. "
            "Easily cloned with Proxmark or consumer RFID tools."
        ),
    },

    # ── HF 13.56 MHz — MIFARE ────────────────────────────────────────────────

    "MIFARE_CLASSIC_1K": {
        "family":       "HF 13.56 MHz — MIFARE Classic 1K",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "Crypto1",
        "broken_crypto": True,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "notes": (
            "Crypto1 cipher (48-bit proprietary) is completely broken. "
            "Vulnerable to MFOC (Nested Auth), Darkside, and mfkey32 attacks. "
            "Full sector dump possible in seconds with Proxmark3. "
            "SAK=08 / ATQA=00 04."
        ),
    },

    "MIFARE_CLASSIC_4K": {
        "family":       "HF 13.56 MHz — MIFARE Classic 4K",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "Crypto1",
        "broken_crypto": True,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "notes": (
            "Same Crypto1 weakness as 1K but 4 KB storage. "
            "SAK=18 / ATQA=00 02."
        ),
    },

    "MIFARE_ULTRALIGHT": {
        "family":       "HF 13.56 MHz — MIFARE Ultralight",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": (
            "No encryption. Read-only password optional. "
            "Used in disposable tickets/transport. SAK=00 / ATQA=00 44."
        ),
    },

    "MIFARE_ULTRALIGHT_C": {
        "family":       "HF 13.56 MHz — MIFARE Ultralight C",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "3DES",
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": "3DES authentication, SAK=00.",
    },

    "MIFARE_PLUS_SL1": {
        "family":       "HF 13.56 MHz — MIFARE Plus (Security Level 1)",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "AES / Crypto1",
        "broken_crypto": True,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "notes": (
            "SL1 mode emulates Classic — Crypto1 weaknesses apply. "
            "SAK=28 or 60."
        ),
    },

    "MIFARE_PLUS_SL3": {
        "family":       "HF 13.56 MHz — MIFARE Plus (Security Level 3)",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "notes": "Full AES-128 mutual auth — significantly more secure.",
    },

    # ── HF 13.56 MHz — DESFire ───────────────────────────────────────────────

    "MIFARE_DESFIRE": {
        "family":       "HF 13.56 MHz — MIFARE DESFire",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / ISO7816",
        "crypto":       "3DES / AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "notes": (
            "Secure multi-application card. AES mutual auth. "
            "Used in modern access control / transport. SAK=20 (with ISO14443-4)."
        ),
    },

    "MIFARE_DESFIRE_EV2": {
        "family":       "HF 13.56 MHz — MIFARE DESFire EV2",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "notes": "Enhanced security, transaction MAC, proximity check.",
    },

    # ── HF 13.56 MHz — NTAG ──────────────────────────────────────────────────

    "NTAG213": {
        "family":       "HF 13.56 MHz — NXP NTAG213",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": "NFC Forum Type 2 tag. 144 bytes user memory. No crypto.",
    },

    "NTAG215": {
        "family":       "HF 13.56 MHz — NXP NTAG215",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes": "504 bytes user memory. Used in Amiibo figures.",
    },

    # ── HF 13.56 MHz — EMV Payment ───────────────────────────────────────────

    "EMV_PAYMENT": {
        "family":       "HF 13.56 MHz — EMV Contactless Payment Card",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / EMVCo",
        "crypto":       "RSA / AES (dynamic)",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": True,
        "notes": (
            "Cryptographic contactless payment card (Visa, Mastercard, Amex etc.). "
            "Each transaction uses a unique cryptogram — replay attacks are blocked. "
            "Relay attack is theoretically possible within transaction window. "
            "Static PAN/expiry may be readable without authentication (skimming risk). "
            "SAK=20 / ATQA=00 48 (NXP chip)."
        ),
    },

    # ── Fallback ──────────────────────────────────────────────────────────────

    "UNKNOWN": {
        "family":       "Unknown / Unrecognised",
        "freq":         "Unknown",
        "standard":     "Unknown",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "notes":        "Card type could not be determined from the log.",
    },
}
