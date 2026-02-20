CARD_DATABASE = {
    "EM410X": {
        "family": "LF 125 kHz",
        "crypto": False,
        "mutual_auth": False,
        "static_uid": True
    },
    "MIFARE_CLASSIC": {
        "family": "HF ISO14443",
        "crypto": "CRYPTO1",
        "broken_crypto": True,
        "mutual_auth": False,
        "static_uid": False
    },
    "DESFIRE": {
        "family": "HF ISO14443",
        "crypto": "AES",
        "mutual_auth": True,
        "static_uid": False
    },
    "EMV": {
        "family": "HF ISO14443",
        "crypto": "RSA/AES",
        "mutual_auth": True,
        "payment_card": True
    }
}
