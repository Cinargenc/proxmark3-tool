from fingerprint_engine import identify_card
from card_profiles import CARD_DATABASE
from parser import parse_log

from analyzers.uid_analysis import analyze_uid
from analyzers.protocol_analysis import analyze_protocol
from analyzers.timing_analysis import analyze_timing
from analyzers.emv_analysis import analyze_emv
from analyzers.lf_analysis import analyze_lf

from scoring import calculate_score
from threat_engine import assess_attacks
from report import generate_report

import sys


if len(sys.argv) != 2:
    print("Usage: python3 main.py logfile.txt")
    sys.exit(1)


# ----------------------------------------------------------
# 1️⃣ Parse Log
# ----------------------------------------------------------
log_path = sys.argv[1]
log_data = parse_log(log_path)

# ----------------------------------------------------------
# 2️⃣ Fingerprint Card Profile
# ----------------------------------------------------------
profile_name = identify_card(log_data)

profile = CARD_DATABASE.get(profile_name, {
    "family": "Unknown",
    "crypto": False,
    "mutual_auth": False,
    "static_uid": True
})

card = {
    "family": profile.get("family", "Unknown"),
    "profile": profile_name
}


# ----------------------------------------------------------
# 3️⃣ Analyzer Layer (Family bağımsız çalışır)
# ----------------------------------------------------------

# UID
try:
    uid_data = analyze_uid(log_data)
except:
    uid_data = {}

# LF özel analiz (varsa override eder)
if profile.get("family") == "LF 125 kHz":
    raw_text = open(log_path).read()
    lf_result = analyze_lf(raw_text)

    uid_data.update({
        "length": len(lf_result.get("uid", "")),
        "entropy": lf_result.get("entropy", "Low"),
        "clone_risk": lf_result.get("clone_risk", "Very High")
    })

# Protocol
try:
    protocol_data = analyze_protocol(log_data)
except:
    protocol_data = {}

# Timing
try:
    timing_data = analyze_timing(log_data)
except:
    timing_data = {}

# EMV / Application
try:
    emv_data = analyze_emv(log_data)
except:
    emv_data = {}


# ----------------------------------------------------------
# 4️⃣ Threat Simulation (Profile-aware)
# ----------------------------------------------------------
attacks = assess_attacks(profile, uid_data)


# ----------------------------------------------------------
# 5️⃣ Risk Scoring (Profile-aware)
# ----------------------------------------------------------
score, risk = calculate_score(
    profile,        # artık family değil profile gönderiyoruz
    uid_data,
    protocol_data,
    timing_data,
    emv_data
)


# ----------------------------------------------------------
# 6️⃣ Report Generation
# ----------------------------------------------------------
generate_report(
    card,
    uid_data,
    protocol_data,
    timing_data,
    emv_data,
    score,
    risk,
    attacks
)
