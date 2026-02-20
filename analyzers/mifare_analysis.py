"""
MIFARE Classic / Crypto1 specific security analysis module.

Crypto1 is a proprietary 48-bit stream cipher that was reverse-engineered
in 2008 (Nohl et al.).  Multiple practical attacks exist:

  1. Darkside attack      – recovers master key from parity bits
  2. Nested auth attack   – leverages a known sector key to attack others
  3. Hard-nested attack   – works even without any known key
  4. mfkey32 / mfkey64   – recover key from two reader/tag nonces
"""


def analyze_mifare(data: dict, profile: dict) -> dict:
    """
    Return a dict of Mifare Classic attack feasibility information.
    Only meaningful when profile["crypto"] == "Crypto1".
    """
    result = {}

    is_classic = profile.get("crypto") == "Crypto1"
    is_broken  = profile.get("broken_crypto", False)

    result["crypto1_present"] = is_classic
    result["crypto1_broken"]  = is_broken

    if not is_classic:
        result["summary"] = "Not a MIFARE Classic card — Crypto1 attacks do not apply."
        return result

    # ── Attack feasibility ────────────────────────────────────────────────────

    result["attacks"] = {

        "darkside": {
            "feasibility": "High",
            "description": (
                "Darkside attack (Garcia et al. 2009) exploits a PRNG weakness. "
                "Works even without any prior knowledge of sector keys. "
                "Takes a few seconds with Proxmark3."
            ),
            "proxmark_cmd": "hf mf darkside",
        },

        "nested_auth": {
            "feasibility": "Very High",
            "description": (
                "If at least one sector key is known (e.g., default key), "
                "the nested authentication attack recovers all remaining keys "
                "in minutes. Most Classic 1K cards use default keys on sector 0."
            ),
            "proxmark_cmd": "hf mf nested --1k --ks",
        },

        "hard_nested": {
            "feasibility": "Medium",
            "description": (
                "Hard-nested attack works when no keys are known. "
                "Slower than nested but still practical (~30 minutes)."
            ),
            "proxmark_cmd": "hf mf hardnested -s 0 -a",
        },

        "mfkey32": {
            "feasibility": "High",
            "description": (
                "If the card interacts with a legitimate reader, the "
                "reader/tag nonce exchange can be sniffed and the session key "
                "recovered offline with mfkey32 in seconds."
            ),
            "proxmark_cmd": "hf mf mfkey32",
        },

        "full_dump": {
            "feasibility": "Very High",
            "description": (
                "Once all sector keys are recovered, a full memory dump "
                "can be obtained and cloned to a writable MIFARE card."
            ),
            "proxmark_cmd": "hf mf dump --1k",
        },

        "clone": {
            "feasibility": "High",
            "description": (
                "MIFARE Classic 1K cards can be fully cloned to magic/UID-writable "
                "blank cards (Chinese magic card, CUID, FUID)."
            ),
            "proxmark_cmd": "hf mf cload --file dump.bin",
        },
    }

    # ── Default key check ─────────────────────────────────────────────────────
    result["default_keys"] = [
        "FF FF FF FF FF FF  (factory default)",
        "A0 A1 A2 A3 A4 A5",
        "D3 F7 D3 F7 D3 F7",
        "00 00 00 00 00 00",
    ]
    result["default_key_note"] = (
        "Many deployed MIFARE Classic cards still use factory-default keys "
        "on one or more sectors. Try: hf mf chk --1k"
    )

    result["proxmark_checklist"] = [
        "hf mf chk --1k                    # Check default/known keys",
        "hf mf darkside                    # Recover first key (no prior knowledge)",
        "hf mf nested --1k --ks            # Recover all keys once one is known",
        "hf mf dump --1k                   # Full memory dump",
        "hf mf cload --file dump.bin       # Clone to magic card",
        "hf mf hardnested -s 0 -a          # Hard-nested (no known key)",
    ]

    result["summary"] = (
        "MIFARE Classic uses the Crypto1 cipher which is completely broken. "
        "All sectors can be dumped and the card cloned within minutes using "
        "a Proxmark3 device."
    )

    return result
