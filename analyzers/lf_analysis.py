import re


def analyze_lf(data_or_content) -> dict:
    """
    Analyse LF (125 kHz) tag data.

    Accepts either:
      - a dict (parsed log_data from parse_log)
      - a raw string (legacy call path)
    """
    result = {}

    # ── Normalise input ───────────────────────────────────────────────────────
    if isinstance(data_or_content, dict):
        content = data_or_content.get("raw_content", "")
        lf_id       = data_or_content.get("lf_id", "")
        unique_id   = data_or_content.get("lf_unique_id", "")
        lf_type     = data_or_content.get("lf_type", "EM410x")
        rf_rate     = data_or_content.get("lf_rf_rate")
        dez8        = data_or_content.get("lf_dez_8")
        dez10       = data_or_content.get("lf_dez_10")
        paxton      = data_or_content.get("lf_paxton")
        sebury      = data_or_content.get("lf_sebury")
    else:
        content     = data_or_content
        lf_id       = ""
        unique_id   = ""
        lf_type     = "EM410x"
        rf_rate     = None
        dez8 = dez10 = paxton = sebury = None

        m = re.search(r'EM\s*410x?\s*ID\s*[:\s]*([0-9A-Fa-f]{8,12})', content, re.IGNORECASE)
        if m:
            lf_id = m.group(1).upper()

        m = re.search(r'Unique TAG ID\s*:\s*([0-9A-Fa-f]+)', content)
        if m:
            unique_id = m.group(1).upper()

        m = re.search(r'DEZ 8\s*:\s*(\S+)', content)
        if m:
            dez8 = m.group(1)

        m = re.search(r'DEZ 10\s*:\s*(\S+)', content)
        if m:
            dez10 = m.group(1)

        m = re.search(r'Pattern Paxton\s*:\s*(\d+)', content)
        if m:
            paxton = m.group(1)

    # ── Build result ──────────────────────────────────────────────────────────
    result["type"]      = lf_type if lf_type else "EM410x"
    result["uid"]       = lf_id
    result["unique_id"] = unique_id

    if rf_rate:
        result["rf_rate"] = f"RF/{rf_rate}"

    if dez8:
        result["dez8"]   = dez8
    if dez10:
        result["dez10"]  = dez10
    if paxton:
        result["paxton"] = paxton
    if sebury:
        result["sebury"] = sebury

    # ── Security ──────────────────────────────────────────────────────────────
    result["clone_risk"]  = "Very High"
    result["entropy"]     = "Low"

    result["security_notes"] = (
        "LF 125 kHz tags transmit their ID in plaintext with NO encryption. "
        "The signal can be read from up to ~30 cm with consumer hardware. "
        "A T5577 writable blank card can emulate any EM410x ID."
    )

    # ── Proxmark clone commands ───────────────────────────────────────────────
    clone_cmds = []
    if lf_id:
        clone_cmds.append(f"lf em 410x clone --id {lf_id}")
        clone_cmds.append(f"lf em 410x sim --id {lf_id}")
    if paxton:
        clone_cmds.append(f"lf hid clone -r {paxton}")
    result["clone_commands"] = clone_cmds

    return result
