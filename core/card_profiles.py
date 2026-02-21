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
#    transit_card  : True for transit/bus/metro cards
#    access_card   : True for physical access control cards
#    notes         : Extra human-readable notes
# ──────────────────────────────────────────────────────────────────────────────

CARD_DATABASE = {

    # ══════════════════════════════════════════════════════════════════════════
    #  LF 125 kHz — Low Frequency
    # ══════════════════════════════════════════════════════════════════════════

    "EM410X": {
        "family":       "LF 125 kHz — EM410x",
        "freq":         "125 kHz",
        "standard":     "Proprietary (EM Microelectronic)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "No encryption whatsoever. UID transmitted in plain. "
            "Clone with T5577 writer or Proxmark lf em 410x clone command. "
            "Widely used in legacy access control, turnstiles, cafeteria gates — "
            "extremely insecure. Reading range: 5–30 cm."
        ),
    },

    "EM4200": {
        "family":       "LF 125 kHz — EM4200 (Read-Only)",
        "freq":         "125 kHz",
        "standard":     "Proprietary (EM Microelectronic)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "Read-only variant of EM4xxx series. Factory-programmed UID only. "
            "Slightly harder to clone than T5577-based cards, but UID is still "
            "transmitted in plaintext. Used in animal tags and industrial ID."
        ),
    },

    "T5577": {
        "family":       "LF 125 kHz — T5577 (Multi-Protocol Writable)",
        "freq":         "125 kHz",
        "standard":     "Proprietary (Atmel/various)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "Writable multi-protocol LF blank card. Can emulate EM410x, HID, "
            "Indala, AWID and many other LF protocols. The standard clone target "
            "when attacking LF access control systems. "
            "Proxmark3: lf t55xx detect / lf t55xx write"
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
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "HID Proximity — no encryption. Wiegand output AC system. "
            "Extremely common in corporate turnstiles, buildings, parking. "
            "Easily cloned with Proxmark or consumer RFID tools. "
            "Proxmark3: lf hid read / lf hid clone"
        ),
    },

    "AWID": {
        "family":       "LF 125 kHz — AWID",
        "freq":         "125 kHz",
        "standard":     "Proprietary (AWID Systems)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "AWID LF proximity format. No encryption, Wiegand output. "
            "Used in some access control systems in North America. "
            "Proxmark3: lf awid read / lf awid clone"
        ),
    },

    "INDALA": {
        "family":       "LF 125 kHz — Indala",
        "freq":         "125 kHz",
        "standard":     "Proprietary (Motorola/HID Global)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "Indala LF format (now owned by HID Global). No encryption. "
            "Used in legacy access control, hospitals, campuses. "
            "Proxmark3: lf indala read / lf indala clone"
        ),
    },

    "PARADOX": {
        "family":       "LF 125 kHz — Paradox",
        "freq":         "125 kHz",
        "standard":     "Proprietary (Paradox Security Systems)",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "Paradox LF alarm/access format. No encryption. "
            "Used in Paradox security panels. "
            "Proxmark3: lf paradox read / lf paradox clone"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — MIFARE (NXP)
    # ══════════════════════════════════════════════════════════════════════════

    "MIFARE_MINI": {
        "family":       "HF 13.56 MHz — MIFARE Mini",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "Crypto1",
        "broken_crypto": True,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Smallest MIFARE Classic variant (320 bytes, 5 sectors). "
            "Same broken Crypto1 cipher — all attacks apply. "
            "SAK=09 / ATQA=00 04. Used in hotel keys, small-scale transit."
        ),
    },

    "MIFARE_CLASSIC_1K": {
        "family":       "HF 13.56 MHz — MIFARE Classic 1K",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "Crypto1",
        "broken_crypto": True,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Crypto1 cipher (48-bit proprietary) is completely broken. "
            "Vulnerable to MFOC (Nested Auth), Darkside, and mfkey32 attacks. "
            "Full sector dump possible in seconds with Proxmark3. "
            "Widely used in cafeteria cards, university campus cards, "
            "older bus systems, turnstiles, hotel keys. SAK=08 / ATQA=00 04."
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
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Same Crypto1 weakness as 1K but 4 KB storage (40 sectors). "
            "Used in transit systems needing more data storage. "
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
        "transit_card": True,
        "access_card":  False,
        "notes": (
            "No encryption. Optional read-only password. "
            "Very cheap — used in disposable single-trip bus/metro tickets, "
            "event wristbands. SAK=00 / ATQA=00 44."
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
        "transit_card": True,
        "access_card":  False,
        "notes": (
            "3DES authentication added to Ultralight. "
            "Used in multi-trip transit tickets, loyalty cards. "
            "3DES itself is not broken but implementation weaknesses possible. "
            "SAK=00 / ATQA=00 44."
        ),
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
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "SL1 mode emulates MIFARE Classic — all Crypto1 weaknesses apply. "
            "Often deployed as a drop-in Classic replacement but left in SL1. "
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
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Full AES-128 mutual authentication. Significantly more secure than Classic. "
            "Used in modern transit and access control where Classic migration occurred. "
            "SAK=28 or 60 (same as SL1 — distinguish via ATS/authentication response)."
        ),
    },

    "MIFARE_DESFIRE": {
        "family":       "HF 13.56 MHz — MIFARE DESFire EV1",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / ISO7816",
        "crypto":       "3DES / AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Secure multi-application card. Mutual AES authentication. "
            "Used in modern transit (İstanbulkart, Ankarakart, Oyster, OV-Chipkaart), "
            "cafeteria systems, university access, corporate security. "
            "SAK=20 (ISO14443-4). ATS distinguishes from EMV."
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
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Enhanced DESFire with transaction MAC, proximity check, "
            "and delegated application management. Used in newer transit and "
            "high-security access control. SAK=20."
        ),
    },

    "MIFARE_DESFIRE_EV3": {
        "family":       "HF 13.56 MHz — MIFARE DESFire EV3",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A",
        "crypto":       "AES-128 / ECC",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Latest DESFire generation. Adds Secure Unique NFC Message (SUN) "
            "and NFC-enabled cloud verification. Highest security in the MIFARE family. "
            "SAK=20. ATS identifies EV3 version."
        ),
    },

    # ── NTAG Series ─────────────────────────────────────────────────────────

    "NTAG213": {
        "family":       "HF 13.56 MHz — NXP NTAG213",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / NFC Forum Type 2",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "NFC Forum Type 2 tag. 144 bytes user memory. No crypto. "
            "Used in NFC stickers, smart posters, product authentication, "
            "basic loyalty cards. SAK=00 / ATQA=00 44."
        ),
    },

    "NTAG215": {
        "family":       "HF 13.56 MHz — NXP NTAG215",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / NFC Forum Type 2",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "504 bytes user memory. Used in Amiibo figures, game cards, "
            "NFC business cards. SAK=00 / ATQA=00 44."
        ),
    },

    "NTAG216": {
        "family":       "HF 13.56 MHz — NXP NTAG216",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / NFC Forum Type 2",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "Largest standard NTAG — 888 bytes user memory. "
            "Used where more NFC data storage needed (vCards, URLs, config). "
            "SAK=00 / ATQA=00 44."
        ),
    },

    "NTAG424_DNA": {
        "family":       "HF 13.56 MHz — NXP NTAG424 DNA",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / ISO7816",
        "crypto":       "AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "Secure NFC tag with AES-128 mutual auth, SDM (Secure Dynamic Messaging). "
            "Used in brand protection, luxury goods authentication, secure NFC wristbands. "
            "SAK=20 / ATQA=00 44. Generates unique encrypted payload per scan."
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — HID iCLASS Family
    # ══════════════════════════════════════════════════════════════════════════

    "HID_ICLASS": {
        "family":       "HF 13.56 MHz — HID iCLASS",
        "freq":         "13.56 MHz",
        "standard":     "ISO15693 (Vicinity)",
        "crypto":       "DES / 3DES",
        "broken_crypto": True,
        "mutual_auth":  True,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "HID iCLASS — uses proprietary DES-based cipher. "
            "FULLY BROKEN: master diversification key was leaked ('iclass_crack'). "
            "Any iCLASS card can be cloned given the master key. "
            "Extremely common in corporate buildings, universities, hospitals, "
            "cafeteria/yemekhane access, and turnstile systems. "
            "Proxmark3: hf iclass read / hf iclass dump / hf iclass clone"
        ),
    },

    "HID_ICLASS_SE": {
        "family":       "HF 13.56 MHz — HID iCLASS SE / Seos",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / ISO15693",
        "crypto":       "AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "HID iCLASS SE and Seos — modern replacements using AES-128. "
            "Significantly more secure than original iCLASS. "
            "Used in newer corporate, government, and high-security installations. "
            "Proxmark3: hf iclass info (limited analysis possible)"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — LEGIC
    # ══════════════════════════════════════════════════════════════════════════

    "LEGIC_PRIME": {
        "family":       "HF 13.56 MHz — LEGIC Prime",
        "freq":         "13.56 MHz",
        "standard":     "Proprietary (LEGIC Identsystems)",
        "crypto":       "Proprietary stream cipher",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "LEGIC Prime — proprietary Swiss RF-ID system. "
            "Used in European healthcare, industrial, and facility management systems. "
            "Multi-application card. Proprietary cipher — not publicly broken but audited. "
            "Proxmark3: hf legic info / hf legic reader"
        ),
    },

    "LEGIC_ADVANT": {
        "family":       "HF 13.56 MHz — LEGIC advant",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A/B, ISO15693",
        "crypto":       "AES-128",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "LEGIC advant — modern successor to Prime with AES-128. "
            "Supports ISO standards. Used in high-security access, time management, "
            "vending/cafeteria, and cashless payment. "
            "Proxmark3: hf legic info"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — FeliCa (Sony)
    # ══════════════════════════════════════════════════════════════════════════

    "FELICA": {
        "family":       "HF 13.56 MHz — Sony FeliCa",
        "freq":         "13.56 MHz",
        "standard":     "ISO18092 / JIS X 6319-4",
        "crypto":       "Triple-DES / AES",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  True,
        "notes": (
            "Sony FeliCa — dominant in Japan (Suica, PASMO, Oyster-style) "
            "and Hong Kong (Octopus Card). Also used in Singapore (EZ-Link). "
            "NFC Forum Type 3. Very fast transaction speed (212/424 kbps). "
            "Proxmark3: hf felica reader / hf felica raw"
        ),
    },

    "FELICA_LITE": {
        "family":       "HF 13.56 MHz — Sony FeliCa Lite",
        "freq":         "13.56 MHz",
        "standard":     "ISO18092",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": True,
        "access_card":  False,
        "notes": (
            "Simplified FeliCa without encryption. "
            "Used in paper/disposable transit tickets. "
            "Proxmark3: hf felica reader"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — ISO14443-B (Type B) Cards
    # ══════════════════════════════════════════════════════════════════════════

    "ISO14443B_PAYMENT": {
        "family":       "HF 13.56 MHz — ISO14443-B Contactless Payment",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-B / EMVCo",
        "crypto":       "RSA / AES (dynamic)",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": True,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "ISO14443 Type B contactless payment (e.g., some French bank cards, "
            "older European debit cards). Same EMV cryptographic protections apply. "
            "PUPI (4 bytes) is the Type-B equivalent of UID. "
            "Proxmark3: hf 14b reader / emv reader"
        ),
    },

    "CALYPSO": {
        "family":       "HF 13.56 MHz — Calypso Transit Card",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-B / CEN EN1545",
        "crypto":       "Triple-DES / AES",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": False,
        "transit_card": True,
        "access_card":  False,
        "notes": (
            "Calypso — open standard for transit smart cards (ISO14443-B). "
            "Used in Paris Navigo, Brussels MOBIB, Lisbon Viva, Lyon TCL, "
            "Brazilian transit systems. Multi-application, Triple-DES secured. "
            "Proxmark3: hf 14b reader / hf calypso reader"
        ),
    },

    "ST25TB": {
        "family":       "HF 13.56 MHz — ST25TB / SRI (STMicroelectronics)",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-B",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": True,
        "access_card":  False,
        "notes": (
            "STMicroelectronics ST25TB (formerly SRI512/SRI2K). ISO14443-B Type B. "
            "Used heavily in French transit tickets (RATP, SNCF paper tickets), "
            "parking tickets, loyalty cards. No encryption — UID is static. "
            "Proxmark3: hf 14b reader"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — ISO15693 (Vicinity / Long Range)
    # ══════════════════════════════════════════════════════════════════════════

    "ISO15693": {
        "family":       "HF 13.56 MHz — ISO15693 (Vicinity Card)",
        "freq":         "13.56 MHz",
        "standard":     "ISO15693",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  True,
        "notes": (
            "Vicinity standard — longer read range (up to 1 m) vs. ISO14443. "
            "Used in library book tags, medical wristbands, asset tracking, "
            "industrial supply chains, some older access control. No encryption. "
            "Proxmark3: hf 15 reader / hf 15 dump"
        ),
    },

    "ICODE_SLIX": {
        "family":       "HF 13.56 MHz — NXP ICODE SLIX",
        "freq":         "13.56 MHz",
        "standard":     "ISO15693",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "NXP ICODE SLIX — ISO15693 tag with optional privacy/password protection. "
            "Used in retail (EAS anti-theft), library management (RFID books), "
            "healthcare item tracking. Proxmark3: hf 15 reader"
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  HF 13.56 MHz — EMV Payment Cards
    # ══════════════════════════════════════════════════════════════════════════

    "EMV_PAYMENT": {
        "family":       "HF 13.56 MHz — EMV Contactless Payment Card",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / EMVCo",
        "crypto":       "RSA / AES (dynamic)",
        "broken_crypto": False,
        "mutual_auth":  True,
        "static_uid":   False,
        "payment_card": True,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "Modern contactless credit/debit card (Visa, Mastercard, Amex, Troy, etc.). "
            "Each transaction uses a unique ARQC cryptogram — replay blocked. "
            "Relay attack possible within transaction window. "
            "Static PAN + expiry readable without auth (skimming/CNP fraud risk). "
            "SAK=20 / ATQA=00 48 (NXP chip variant)."
        ),
    },

    "EMV_PAYMENT_OLD": {
        "family":       "HF 13.56 MHz — Older Contactless Payment (Pre-EMV 2.x)",
        "freq":         "13.56 MHz",
        "standard":     "ISO14443-A / EMVCo 1.x",
        "crypto":       "RSA (static)",
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   False,
        "payment_card": True,
        "transit_card": False,
        "access_card":  False,
        "notes": (
            "Pre-2014 contactless cards may lack full dynamic cryptogram support. "
            "Some earlier implementations allowed offline static transactions. "
            "Track-2 equivalent data + static PAN may be more accessible. "
            "Proxmark3: emv reader — check for CDA (Combined DDA/Application Cryptogram)."
        ),
    },

    # ══════════════════════════════════════════════════════════════════════════
    #  Fallback
    # ══════════════════════════════════════════════════════════════════════════

    "UNKNOWN": {
        "family":       "Unknown / Unrecognised",
        "freq":         "Unknown",
        "standard":     "Unknown",
        "crypto":       False,
        "broken_crypto": False,
        "mutual_auth":  False,
        "static_uid":   True,
        "payment_card": False,
        "transit_card": False,
        "access_card":  False,
        "notes":        "Card type could not be determined from the log.",
    },
}
