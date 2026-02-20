import re

def analyze_lf(content):

    result = {}

    match = re.search(r"EM\s*410x\s*ID\s*([0-9A-F]+)", content)

    if match:
        result["type"] = "EM410x"
        result["uid"] = match.group(1)
        result["clone_risk"] = "Very High"
    else:
        result["type"] = "Unknown LF"
        result["uid"] = ""
        result["clone_risk"] = "Unknown"

    return result
