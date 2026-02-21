import re
import os

# ──────────────────────────────────────────────────────────
#  HELPERS
# ──────────────────────────────────────────────────────────

def _clean(content: str) -> str:
    """Strip ANSI escape codes and carriage-return noise."""
    content = re.sub(r'\x1b\[[0-9;]*m', '', content)
    content = re.sub(r'\r', '\n', content)
    return content


def _probe_mode(content: str) -> str:
    """Detect whether the log is from hf search or lf search."""
    if re.search(r'lf search', content, re.IGNORECASE):
        return "LF"
    if re.search(r'hf search', content, re.IGNORECASE):
        return "HF"
    # Fallback: look for known HF markers
    if "ISO14443-A" in content or "SAK:" in content:
        return "HF"
    if "ISO14443-B" in content or "PUPI" in content or "Calypso" in content:
        return "HF"
    if "FeliCa" in content or "felica" in content.lower():
        return "HF"
    if "iCLASS" in content or "LEGIC" in content:
        return "HF"
    if "EM 410x" in content or "EM410x" in content:
        return "LF"
    if "HID Prox" in content or "Indala" in content or "AWID" in content:
        return "LF"
    return "UNKNOWN"


# ──────────────────────────────────────────────────────────
#  HF PARSER
# ──────────────────────────────────────────────────────────

def _parse_hf(content: str, data: dict):
    """Parse ISO14443-A / HF search output."""

    # UID  (e.g. "UID: 04 43 BF 22 3E 18 90")
    m = re.search(r'UID\s*:\s*([0-9A-Fa-f][0-9A-Fa-f\s]+?)(?:\s*\(|$|\n)', content)
    if m:
        raw_uid = m.group(1).strip()
        data["uid_raw"] = raw_uid
        data["uid_bytes"] = raw_uid.upper().split()

    # ATQA  (e.g. "ATQA: 00 48")
    m = re.search(r'ATQA\s*:\s*([0-9A-Fa-f\s]{4,9})', content)
    if m:
        data["atqa"] = m.group(1).strip().upper()

    # SAK  (e.g. "SAK: 20 [1]")
    m = re.search(r'SAK\s*:\s*([0-9A-Fa-f]{1,2})', content)
    if m:
        data["sak"] = m.group(1).upper().zfill(2)   # normalise to 2 hex digits

    # ATS line
    m = re.search(r'ATS\s*:\s*([0-9A-Fa-f\s]+?)(?:\[|$|\n)', content)
    if m:
        data["ats_raw"] = m.group(1).strip()

    # FWI  (from TB1 line  "FWI = 7")
    m = re.search(r'FWI\s*[=:]\s*(\d+)', content)
    if m:
        data["fwi"] = int(m.group(1))

    # SFGI
    m = re.search(r'SFGI\s*[=:]\s*(\d+)', content)
    if m:
        data["sfgi"] = int(m.group(1))

    # CID
    data["cid"] = bool(re.search(r'CID is supported', content))

    # APDU / ISO14443-4
    data["apdu"] = bool(re.search(r'ISO14443-4 Smartcard|SAK.*20', content)
                        or data.get("sak") == "20")

    # Manufacturer  (e.g. "NXP Semiconductors Germany")
    m = re.search(r'\[\+\]\s+(NXP|Infineon|Samsung|STMicro|Atmel|NXP Semiconductors[^\n]*)', content)
    if m:
        data["manufacturer"] = m.group(1).strip()

    # EMV detection
    data["emv"] = bool(re.search(r'Possible types.*EMV|EMV', content, re.DOTALL))

    # MIFARE Classic detection via text
    data["mifare_classic"] = bool(re.search(r'MIFARE Classic', content, re.IGNORECASE))

    # DESFire
    data["desfire"] = bool(re.search(r'DESFire|DESFIRE', content, re.IGNORECASE))

    # FeliCa
    data["felica"] = bool(re.search(r'FeliCa|felica', content, re.IGNORECASE))

    # iCLASS
    data["iclass"] = bool(re.search(r'iCLASS|iClass', content, re.IGNORECASE))

    # LEGIC
    data["legic"] = bool(re.search(r'LEGIC', content, re.IGNORECASE))

    # Calypso
    data["calypso"] = bool(re.search(r'Calypso|NAVIGO|MOBIB', content, re.IGNORECASE))

    # ISO14443-B
    data["iso14443b"] = bool(re.search(r'ISO14443-B|ISO14443B|PUPI', content, re.IGNORECASE))

    # Possible types block
    m = re.search(r'Possible types:\s*(.*?)(?=\[=\]|\Z)', content, re.DOTALL)
    if m:
        data["possible_types"] = m.group(1).strip()


# ──────────────────────────────────────────────────────────
#  LF PARSER
# ──────────────────────────────────────────────────────────

def _parse_lf(content: str, data: dict):
    """Parse LF (125 kHz) search output."""

    # EM410x primary ID  (e.g. "EM 410x ID 4B0077255C")
    m = re.search(r'EM\s*410x?\s*ID\s*[:\s]*([0-9A-Fa-f]{8,12})', content, re.IGNORECASE)
    if m:
        data["lf_type"] = "EM410x"
        data["lf_id"] = m.group(1).upper()

    # Unique scrambled TAG ID
    m = re.search(r'Unique TAG ID\s*:\s*([0-9A-Fa-f]+)', content)
    if m:
        data["lf_unique_id"] = m.group(1).upper()

    # DEZ formats
    for label in ["DEZ 8", "DEZ 10", "DEZ 5.5"]:
        pattern = label.replace(".", r"\.")
        m = re.search(rf'{pattern}\s*:\s*(\S+)', content)
        if m:
            data[f"lf_{label.replace(' ', '_').lower()}"] = m.group(1)

    # Paxton pattern
    m = re.search(r'Pattern Paxton\s*:\s*(\d+)', content)
    if m:
        data["lf_paxton"] = m.group(1)

    # Sebury pattern
    m = re.search(r'Pattern Sebury\s*:\s*([\d\s]+)', content)
    if m:
        data["lf_sebury"] = m.group(1).strip()

    # RF rate
    m = re.search(r'EM410x\s*\(\s*RF/(\d+)\s*\)', content)
    if m:
        data["lf_rf_rate"] = int(m.group(1))

    # HID detection
    if re.search(r'HID Prox', content, re.IGNORECASE):
        data["lf_type"] = "HID_PROX"

    # AWID
    if re.search(r'AWID', content, re.IGNORECASE):
        data["lf_type"] = "AWID"

    # Indala / Motorola
    m = re.search(r'Indala\s+ID\s*[:\s]*([0-9A-Fa-f]+)', content, re.IGNORECASE)
    if m:
        data["lf_type"] = "INDALA"
        data["lf_id"] = m.group(1).upper()
    elif re.search(r'Indala|Motorola', content, re.IGNORECASE):
        data["lf_type"] = "INDALA"

    # Paradox
    if re.search(r'Paradox', content, re.IGNORECASE):
        data["lf_type"] = "PARADOX"

    # T5577 / T55xx
    if re.search(r'T5577|T55xx|T55X', content, re.IGNORECASE):
        data["lf_type"] = "T5577"

    # EM4200
    if re.search(r'EM4200|EM 4200', content, re.IGNORECASE):
        data["lf_type"] = "EM4200"


# ──────────────────────────────────────────────────────────
#  PUBLIC API
# ──────────────────────────────────────────────────────────

def parse_log(filename: str) -> dict:
    with open(filename, "r", errors="replace") as f:
        raw = f.read()

    content = _clean(raw)
    data: dict = {}

    mode = _probe_mode(content)
    data["scan_mode"] = mode          # "HF" | "LF" | "UNKNOWN"
    data["raw_content"] = content     # keep for downstream analysers

    if mode == "HF":
        _parse_hf(content, data)
    elif mode == "LF":
        _parse_lf(content, data)
    else:
        # Try both parsers — maybe the log contains both sections
        _parse_hf(content, data)
        _parse_lf(content, data)

    return data
