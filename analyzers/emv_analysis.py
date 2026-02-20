def analyze_emv(data: dict) -> dict:
    """
    Analyse EMV / contactless payment card risks.
    """
    result = {}

    is_emv = data.get("emv", False)
    result["emv_detected"] = is_emv

    if is_emv:
        # Relay attack: attacker relays communication between card and terminal
        result["relay_risk"] = "Medium"
        result["relay_notes"] = (
            "Contactless EMV cards process transactions over the air. "
            "A relay attack (Ghost/Leech) can extend the effective range "
            "to tens of metres. Transaction window is short but non-zero."
        )

        # Skimming: reading PAN, expiry, (sometimes) cardholder name without PIN
        result["skimming_risk"] = "High"
        result["skimming_notes"] = (
            "Static PAN (card number) and expiry date are typically readable "
            "without authentication using a standard NFC reader. "
            "This is sufficient for some online transactions (CNP fraud). "
            "Track-2 equivalent data should be verified with emv reader command."
        )

        result["replay_risk"] = "Low"
        result["replay_notes"] = (
            "Each transaction generates a unique ARQC cryptogram. "
            "Offline relay-captured transactions cannot be replayed."
        )

        result["recommended_commands"] = [
            "emv reader",
            "emv scan",
            "emv pse",
        ]
    else:
        result["relay_risk"] = "Low"
        result["relay_notes"] = "Not an EMV card."
        result["skimming_risk"] = "Low"
        result["skimming_notes"] = "Not an EMV card."
        result["replay_risk"] = "Low"
        result["replay_notes"] = "Not an EMV card."

    return result
