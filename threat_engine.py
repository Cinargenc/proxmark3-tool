def assess_attacks(profile, uid):

    attacks = {}

    if not profile.get("crypto"):
        attacks["clone"] = "Trivial"
    elif profile.get("broken_crypto"):
        attacks["clone"] = "Moderate"
    else:
        attacks["clone"] = "Hard"

    if not profile.get("mutual_auth"):
        attacks["replay"] = "Easy"
        attacks["relay"] = "Easy"
    else:
        attacks["replay"] = "Hard"
        attacks["relay"] = "Moderate"

    attacks["sniffing"] = "Easy"

    return attacks
