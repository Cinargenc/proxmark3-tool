def generate_report(card, uid, protocol, timing, emv, score, risk, attacks):

    uid = uid or {}
    protocol = protocol or {}
    timing = timing or {}
    emv = emv or {}
    attacks = attacks or {}

    uid.setdefault("length", 0)
    uid.setdefault("entropy", "Unknown")
    uid.setdefault("clone_risk", "Unknown")

    protocol.setdefault("protocol", card.get("family", "Unknown"))
    protocol.setdefault("apdu", False)
    protocol.setdefault("cid_supported", False)

    emv.setdefault("emv_detected", False)
    emv.setdefault("relay_risk", "Low")
    emv.setdefault("skimming_risk", "Low")

    print("\n================ RFID PENETRATION TEST REPORT ================\n")

    # ------------------------------------------------------------
    # 1️⃣ Card Overview
    # ------------------------------------------------------------
    print("==[ CARD OVERVIEW ]==========================================")
    print(f"Card Family: {card.get('family', 'Unknown')}")
    print(f"Protocol Type: {protocol['protocol']}")
    print(f"Possible Application: {'EMV Payment' if emv['emv_detected'] else 'Unknown'}\n")

    # ------------------------------------------------------------
    # 2️⃣ UID Analysis
    # ------------------------------------------------------------
    print("==[ UID SECURITY ANALYSIS ]=================================")
    print(f"UID Length: {uid['length']} bytes")
    print(f"Entropy Level: {uid['entropy']}")
    print(f"Clone Feasibility: {uid['clone_risk']}\n")

    # ------------------------------------------------------------
    # 3️⃣ Protocol Security
    # ------------------------------------------------------------
    print("==[ PROTOCOL SECURITY FEATURES ]=============================")
    print(f"APDU Supported: {protocol['apdu']}")
    print(f"CID Supported: {protocol['cid_supported']}")

    if "fwi" in timing:
        print(f"FWI: {timing.get('fwi')}")
        print(f"Relay Window: {timing.get('relay_window')}")
    print()

    # ------------------------------------------------------------
    # 4️⃣ Attack Feasibility Matrix
    # ------------------------------------------------------------
    print("==[ ATTACK FEASIBILITY ASSESSMENT ]==========================")
    for attack, level in attacks.items():
        print(f"{attack.capitalize()} Attack: {level}")
    print()

    # ------------------------------------------------------------
    # 5️⃣ Application Risk
    # ------------------------------------------------------------
    print("==[ APPLICATION LAYER RISK ]=================================")
    print(f"Relay Risk: {emv['relay_risk']}")
    print(f"Skimming Risk: {emv['skimming_risk']}\n")

    # ------------------------------------------------------------
    # 6️⃣ Final Risk Rating
    # ------------------------------------------------------------
    print("==[ OVERALL SECURITY RATING ]================================")
    print(f"Risk Score: {score} / 100")
    print(f"Risk Category: {risk}")

    # Severity explanation
    if risk in ["CRITICAL", "HIGH"]:
        print("Impact: Immediate exploitation possible with low-cost equipment.")
    elif risk == "MEDIUM":
        print("Impact: Exploitation possible under specific conditions.")
    else:
        print("Impact: Limited practical exploitation scenarios.")

    print()

    # ------------------------------------------------------------
    # 7️⃣ Mitigation Recommendations
    # ------------------------------------------------------------
    print("==[ RECOMMENDED MITIGATIONS ]================================")

    if "LF" in card.get("family", ""):
        print("- Replace LF 125kHz tags with cryptographic HF smart cards (ISO14443-A).")
        print("- Implement mutual authentication protocol.")
        print("- Avoid UID-only access control systems.")

    if not protocol.get("apdu"):
        print("- Implement secure APDU-based challenge-response authentication.")

    if uid.get("clone_risk") in ["Very High", "High"]:
        print("- Deploy rolling identifiers or cryptographic signatures.")

    if emv.get("relay_risk") == "High":
        print("- Introduce distance bounding protocol or transaction timing validation.")

    print("\n==============================================================\n")
