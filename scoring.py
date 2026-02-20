def calculate_score(card, uid, protocol, timing, emv):

    score = 0

    # -----------------------------
    # 1 CARD FAMILY BASE SCORE
    # -----------------------------
    # Not: 'profile' yerine parametre olarak gelen 'card' sözlüğü kullanıldı
    if not card.get("crypto"):
        score += 35

    if card.get("broken_crypto"):
        score += 20

    if not card.get("mutual_auth"):
        score += 15

    if card.get("static_uid"):
        score += 15

    # -----------------------------
    # 2 CLONE RISK
    # -----------------------------
    clone_risk = uid.get("clone_risk", "Unknown")

    if clone_risk == "Very High":
        score += 30
    elif clone_risk == "High":
        score += 20
    elif clone_risk == "Medium":
        score += 10

    # -----------------------------
    # 3 CRYPTO / PROTOCOL
    # -----------------------------
    apdu = protocol.get("apdu", False)
    cid = protocol.get("cid_supported", False)

    if not apdu:
        score += 10

    if not cid:
        score += 5

    # -----------------------------
    # 4 APPLICATION RISK
    # -----------------------------
    relay = emv.get("relay_risk", "Low")
    skimming = emv.get("skimming_risk", "Low")

    if relay == "High":
        score += 10
    if skimming == "High":
        score += 10

    # -----------------------------
    # 5 ENTROPY BONUS / PENALTY
    # -----------------------------
    entropy = uid.get("entropy", "Unknown")

    if entropy == "Low":
        score += 5
    elif entropy == "High":
        score -= 5

    # -----------------------------
    # SCORE NORMALIZATION
    # -----------------------------
    score = max(0, min(score, 100))

    # -----------------------------
    # RISK CATEGORY
    # -----------------------------
    if score >= 75:
        risk = "CRITICAL"
    elif score >= 60:
        risk = "HIGH"
    elif score >= 40:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return score, risk
