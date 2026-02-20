def analyze_emv(data):
    result = {}

    if data.get("emv"):
        result["emv_detected"] = True
        result["relay_risk"] = "Medium"
        result["skimming_risk"] = "Medium"
    else:
        result["emv_detected"] = False
        result["relay_risk"] = "Low"
        result["skimming_risk"] = "Low"

    return result
