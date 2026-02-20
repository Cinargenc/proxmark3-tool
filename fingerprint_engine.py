from card_profiles import CARD_DATABASE

def identify_card(log_data):

    raw = str(log_data).upper()

    if "EM410" in raw:
        return "EM410X"

    if "MIFARE CLASSIC" in raw:
        return "MIFARE_CLASSIC"

    if "DESFIRE" in raw:
        return "DESFIRE"

    if "EMV" in raw:
        return "EMV"

    return "UNKNOWN"

