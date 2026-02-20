import re

def detect_card_family(content):

    if "ISO14443-A" in content:
        return "HF_ISO14443"

    if "lf search" in content.lower() or "EM410" in content:
        return "LF_125KHZ"

    return "UNKNOWN"


def parse_log(filename):

    with open(filename, "r") as f:
        content = f.read()

    data = {}

    data["family"] = detect_card_family(content)

    # HF Parsing
    uid_match = re.search(r"UID:\s*([0-9A-F\s]+)", content)
    if uid_match:
        data["uid"] = uid_match.group(1).strip()

    sak_match = re.search(r"SAK:\s*([0-9A-F]+)", content)
    if sak_match:
        data["sak"] = sak_match.group(1)

    if "Possible types:" in content and "EMV" in content:
        data["emv"] = True
    else:
        data["emv"] = False

    fwi_match = re.search(r"FWI\s*=\s*(\d+)", content)
    if fwi_match:
        data["fwi"] = int(fwi_match.group(1))

    if "CID is supported" in content:
        data["cid"] = True
    else:
        data["cid"] = False

    return data
