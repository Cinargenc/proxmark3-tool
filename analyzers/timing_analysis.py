def analyze_timing(data: dict) -> dict:
    """
    Analyse ISO14443-A timing parameters (FWI, SFGI) from parsed log.
    """
    result = {}

    fwi  = data.get("fwi")
    sfgi = data.get("sfgi")

    # FWT = 256 * 16 * 2^FWI / 13.56 MHz  (in milliseconds)
    FC = 13_560_000  # Hz

    if fwi is not None:
        fwt_cycles = 256 * 16 * (2 ** fwi)
        fwt_ms     = round(fwt_cycles / FC * 1000, 3)

        result["fwi"]        = fwi
        result["fwt_cycles"] = fwt_cycles
        result["fwt_ms"]     = fwt_ms

        if fwi >= 10:
            result["relay_window"]      = "Very Wide"
            result["relay_window_note"] = (
                f"FWI={fwi} → FWT={fwt_ms} ms. Very large timing window — "
                "relay attacks have ample time to forward signals."
            )
        elif fwi >= 7:
            result["relay_window"]      = "Wide"
            result["relay_window_note"] = (
                f"FWI={fwi} → FWT={fwt_ms} ms. Relay attack window is wide "
                "enough for practical exploitation."
            )
        elif fwi >= 4:
            result["relay_window"]      = "Moderate"
            result["relay_window_note"] = (
                f"FWI={fwi} → FWT={fwt_ms} ms. Moderate timing window. "
                "Relay is difficult but not impossible."
            )
        else:
            result["relay_window"]      = "Tight"
            result["relay_window_note"] = (
                f"FWI={fwi} → FWT={fwt_ms} ms. Tight timing — relay is hard."
            )

    if sfgi is not None:
        sfgt_cycles = 256 * 16 * (2 ** sfgi)
        sfgt_ms     = round(sfgt_cycles / FC * 1000, 3)
        result["sfgi"]    = sfgi
        result["sfgt_ms"] = sfgt_ms

    return result
