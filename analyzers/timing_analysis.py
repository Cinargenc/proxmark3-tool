def analyze_timing(data):
    result = {}

    fwi = data.get("fwi", None)

    if fwi is not None:
        result["fwi"] = fwi

        if fwi >= 7:
            result["relay_window"] = "Moderate"
        else:
            result["relay_window"] = "Low"

    return result
