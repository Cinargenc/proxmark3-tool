def analyze_protocol(data):
    result = {}

    sak = data.get("sak", "")

    if sak == "20":
        result["protocol"] = "ISO14443-4 Smartcard"
        result["apdu"] = True
    else:
        result["protocol"] = "Unknown"
        result["apdu"] = False

    result["cid_supported"] = data.get("cid", False)

    return result
