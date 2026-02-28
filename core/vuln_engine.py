"""
vuln_engine.py — RFID/NFC Vulnerability Finding Engine

Generates per-finding CVE-style vulnerability entries with CVSS v3.1 scores,
exploit scenarios, security tier classification, and remediation guidance.

Security Tier (card-level):
  LOW    — Critical / High risk card (highest CVSS ≥ 7.0)
  MEDIUM — Moderate risk card       (highest CVSS 4.1–6.9)
  HIGH   — Secure card              (all findings ≤ 4.0 or no findings)
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ──────────────────────────────────────────────────────────────────────────────
#  Data classes
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnFinding:
    vuln_id:        str           # e.g. RFID-001
    title:          str
    description:    str           # Why this is a problem
    exploit_scenario: str         # Concrete step-by-step attack
    cvss_vector:    str           # CVSS v3.1 vector string
    cvss_score:     float         # 0.0 – 10.0
    cvss_severity:  str           # NONE / LOW / MEDIUM / HIGH / CRITICAL
    remediation:    str           # Concrete fix


# ──────────────────────────────────────────────────────────────────────────────
#  CVSS severity helper
# ──────────────────────────────────────────────────────────────────────────────

def _severity(score: float) -> str:
    if score == 0.0:
        return "NONE"
    elif score < 4.0:
        return "LOW"
    elif score < 7.0:
        return "MEDIUM"
    elif score < 9.0:
        return "HIGH"
    else:
        return "CRITICAL"


# ──────────────────────────────────────────────────────────────────────────────
#  Individual vuln check functions
# ──────────────────────────────────────────────────────────────────────────────

def _check_no_encryption(profile: dict) -> Optional[VulnFinding]:
    if profile.get("crypto"):
        return None
    return VulnFinding(
        vuln_id="RFID-001",
        title="No Cryptographic Protection — Plaintext Transmission",
        description=(
            "The card transmits its identifier (UID/ID) in plaintext with zero "
            "cryptographic protection. Any RF-capable device within range can read, "
            "record, and clone the card without the card owner's knowledge. "
            "This vulnerability is inherent to the card standard and cannot be fixed "
            "with software configuration alone."
        ),
        exploit_scenario=(
            "1. Attacker positions a Proxmark3 or cheap PN532-based reader "
            "   (< $30) within 5–30 cm of the victim's wallet or badge.\n"
            "2. Card UID / Wiegand data is captured silently in < 1 second.\n"
            "3. Attacker writes captured ID to a T5577 blank card using "
            "   `lf em 410x clone --id <UID>` (LF) or equivalent HF command.\n"
            "4. Clone badge is presented to the reader — access granted or "
            "   cafeteria transaction approved with no additional verification."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=9.3,
        cvss_severity="CRITICAL",
        remediation=(
            "Replace with ISO14443-A cards using AES-128 mutual authentication "
            "(MIFARE DESFire EV2/EV3, MIFARE Plus SL3). "
            "Never use UID-only access control. "
            "Implement challenge-response at the application layer."
        ),
    )


def _check_broken_crypto1(profile: dict) -> Optional[VulnFinding]:
    if not profile.get("broken_crypto"):
        return None
    if "Crypto1" not in str(profile.get("crypto", "")):
        # Could be iCLASS — handled separately
        if not any(x in profile.get("family", "") for x in ["MIFARE", "Plus SL1"]):
            return None
    return VulnFinding(
        vuln_id="RFID-002",
        title="Broken Proprietary Cipher — Crypto1 (MIFARE Classic)",
        description=(
            "The card uses the Crypto1 cipher, a 48-bit proprietary stream cipher "
            "that was fully reverse-engineered and broken in 2008 (Verdult/Garcia/Balasch). "
            "The cipher's weak pseudo-random number generator (PRNG) allows key recovery "
            "with a handful of authentication traces. All 16 sector keys can be extracted "
            "in under 60 seconds using commodity hardware. "
            "Full card memory dump and cloning are trivial."
        ),
        exploit_scenario=(
            "Phase 1 — Key Recovery via Darkside Attack:\n"
            "1. Run `hf mf darkside` on Proxmark3 — exploits the XOR-zero PRNG "
            "   weakness to recover Key A of sector 0 in ~5 seconds.\n\n"
            "Phase 2 — Nested Authentication Attack:\n"
            "2. Using the recovered sector 0 key, run `hf mf nested --1k --ks` "
            "   to recover all remaining sector keys in seconds via nonce correlation.\n\n"
            "Phase 3 — Full Dump & Clone:\n"
            "3. `hf mf dump` exports the complete card contents.\n"
            "4. `hf mf restore` or `hf mf cload` writes data to a MIFARE Magic "
            "   (Gen2) blank card — clone is now indistinguishable from the original."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
        cvss_score=8.6,
        cvss_severity="HIGH",
        remediation=(
            "Migrate all MIFARE Classic cards to MIFARE DESFire EV2 (AES-128) or "
            "MIFARE Plus (upgrade to Security Level 3). "
            "Rotate sector keys immediately and audit for default keys "
            "(`hf mf chk --1k`). "
            "Implement application-level transaction counters to detect cloned cards."
        ),
    )


def _check_broken_iclass(profile: dict) -> Optional[VulnFinding]:
    if not (profile.get("broken_crypto") and "iCLASS" in profile.get("family", "")
            and "SE" not in profile.get("family", "")):
        return None
    return VulnFinding(
        vuln_id="RFID-009",
        title="Leaked Master Key — HID iCLASS DES Cipher Fully Compromised",
        description=(
            "The HID iCLASS card uses a proprietary DES-based cipher whose "
            "master diversification key was publicly leaked (iClass_crack project, 2012). "
            "With the master key known, any iCLASS card can be read and cloned "
            "by anyone with a Proxmark3 and publicly available tools. "
            "All iCLASS (non-SE) deployments worldwide are affected."
        ),
        exploit_scenario=(
            "1. Proxmark3 reads card: `hf iclass reader`.\n"
            "2. Attacker uses leaked master key to derive card-specific key "
            "   (`hf iclass loclass` or `hf iclass lookup`).\n"
            "3. Full dump: `hf iclass dump --ki 0`.\n"
            "4. Clone to blank iCLASS card: `hf iclass clone`.\n"
            "5. Rogue card bypasses turnstile or building access reader."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        cvss_score=9.0,
        cvss_severity="CRITICAL",
        remediation=(
            "Immediately replace all HID iCLASS (non-SE) cards with "
            "HID iCLASS SE or Seos (AES-128). "
            "Enable 'Elite' key mode on readers temporarily for hardened keys. "
            "Conduct a full access audit — assume all iCLASS cards issued "
            "may have been cloned."
        ),
    )


def _check_no_apdu(profile: dict, protocol: dict) -> Optional[VulnFinding]:
    if protocol.get("apdu") or not protocol:
        return None
    # Only relevant for HF cards — LF cards don't support APDU at all by design
    if "LF" in profile.get("family", ""):
        return None
    return VulnFinding(
        vuln_id="RFID-003",
        title="No APDU Secure Messaging — Missing Application Layer Encryption",
        description=(
            "The card does not use ISO7816 APDU-based secure messaging. "
            "Without APDU channels, there is no mechanism to establish "
            "session keys, perform challenge-response authentication, or "
            "encrypt data at the application layer independent of RF. "
            "Communication between the card and reader is unprotected at "
            "the application layer even if the RF layer has some protection."
        ),
        exploit_scenario=(
            "1. Attacker uses Proxmark3 sniff mode (`hf 14a sniff`) to "
            "   passively record all RF exchanges between card and reader.\n"
            "2. Without APDU session encryption, card data / credential "
            "   payloads are readable in plaintext from the captured trace.\n"
            "3. Captured data can be replayed or used to extract identifiers "
            "   without breaking any cryptographic primitive."
        ),
        cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cvss_score=6.5,
        cvss_severity="MEDIUM",
        remediation=(
            "Upgrade to a card platform that supports ISO7816 APDU commands "
            "with secure messaging (e.g., MIFARE DESFire EV2 CommMode.FULL, "
            "NTAG424 DNA SUN messaging). "
            "Implement challenge-response at the application layer using "
            "card-side AES session key derivation."
        ),
    )


def _check_no_mutual_auth(profile: dict) -> Optional[VulnFinding]:
    if profile.get("mutual_auth") or "LF" in profile.get("family", ""):
        return None
    return VulnFinding(
        vuln_id="RFID-004",
        title="No Mutual Authentication — One-Sided Identity Verification",
        description=(
            "The card does not perform mutual authentication with the reader. "
            "Only the card proves its identity; the reader is never verified. "
            "This allows rogue readers to interact with cards silently "
            "(collecting data or performing transactions without owner consent). "
            "It also means sniffed authentication tokens may be reusable."
        ),
        exploit_scenario=(
            "1. Attacker builds a rogue reader using a Proxmark3 or PN532.\n"
            "2. Rogue reader presents itself near the target's card "
            "   (e.g., in a backpack, through a wallet).\n"
            "3. Card authenticates to rogue reader — credential/session data "
            "   is collected with no indication to the card holder.\n"
            "4. Collected data is forwarded to a legitimate reader in real time "
            "   (relay attack) or replayed later (replay attack)."
        ),
        cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cvss_score=7.5,
        cvss_severity="HIGH",
        remediation=(
            "Use cards that support mutual AES authentication "
            "(MIFARE DESFire EV2+, MIFARE Plus SL3, HID iCLASS SE). "
            "Reader infrastructure must hold a valid key and perform "
            "mutual authentication as specified in ISO14443-4 / ISO7816-4. "
            "Implement certificate pinning where hardware allows."
        ),
    )


def _check_static_uid(uid: dict) -> Optional[VulnFinding]:
    clone_risk = uid.get("clone_risk", "Unknown")
    if clone_risk not in ("Very High", "High"):
        return None
    return VulnFinding(
        vuln_id="RFID-005",
        title="Static / Clonable UID — Identity Can Be Forged",
        description=(
            f"The card's UID has a clone feasibility of '{clone_risk}'. "
            "The UID is static and transmitted without freshness (nonces), "
            "making it trivial to capture and reproduce. "
            "Systems that rely solely on UID matching for access or payment "
            "cannot distinguish a genuine card from a clone."
        ),
        exploit_scenario=(
            "1. Attacker reads card UID: `hf 14a reader` (HF) or `lf em 410x read` (LF).\n"
            "2. Clone to MIFARE Magic Gen1a/Gen2 (HF) or T5577 (LF): "
            "   `hf mf csetuid <UID>` / `lf em 410x clone --id <UID>`.\n"
            "3. Clone card passes UID-only reader authentication.\n"
            "4. In ERP/cafeteria systems, clone card charges to the victim's account."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=7.8,
        cvss_severity="HIGH",
        remediation=(
            "Disable UID-only authentication at all readers. "
            "Move to cryptographic random UID or NDEF-based rolling identifiers. "
            "Implement application-layer mutual authentication that requires "
            "knowledge of a secret key — not just the UID. "
            "For existing systems: add transaction counters and anomaly detection."
        ),
    )


def _check_relay_window(timing: dict, profile: dict) -> Optional[VulnFinding]:
    rw = timing.get("relay_window", "")
    if rw not in ("Very Wide", "Wide"):
        return None
    fwi = timing.get("fwi", "?")
    fwt = timing.get("fwt_ms", "?")
    return VulnFinding(
        vuln_id="RFID-006",
        title=f"Wide Frame Wait Time (FWI={fwi}) — Relay Attack Window Open",
        description=(
            f"The card advertises a Frame Wait Time of {fwt} ms (FWI={fwi}), "
            f"classified as '{rw}'. "
            "A large FWT gives an attacker sufficient time to relay the RF "
            "session over UDP/Wi-Fi from a remote card to a local reader proxy, "
            "effectively extending the card's physical reach across arbitrary distances. "
            "The reader cannot distinguish a relay from a genuine nearby card."
        ),
        exploit_scenario=(
            "1. 'Leech' device near victim's card, 'Ghost' device near target reader.\n"
            "2. Both devices communicate over a low-latency IP link (≤200 ms).\n"
            "3. Reader initiates transaction → Ghost forwards APDU to Leech → "
            "   Leech presents to card → response forwarded back.\n"
            "4. Transaction completes as if card is physically at the reader "
            "   (e.g., contactless payment at a POS terminal in another city)."
        ),
        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
        cvss_score=5.9,
        cvss_severity="MEDIUM",
        remediation=(
            "Request proximity-check / distance-bounding support from "
            "card and reader vendors (ISO/IEC 14443 Annex). "
            "Set application-level transaction time limits. "
            "For payment: lower contactless transaction limits and enable "
            "on-device biometric confirmation (mobile wallets)."
        ),
    )


def _check_emv_skimming(emv: dict) -> Optional[VulnFinding]:
    if not emv.get("emv_detected"):
        return None
    if emv.get("skimming_risk", "Low") not in ("High", "Medium"):
        return None
    return VulnFinding(
        vuln_id="RFID-007",
        title="Contactless PAN Exposure — EMV Static Data Readable Without Auth",
        description=(
            "The card's PAN (Primary Account Number / card number) and expiry date "
            "are readable from the NDEF / EMV data without any authentication. "
            "These fields are sufficient to make card-not-present (CNP) purchases "
            "on merchants that do not enforce CVV2 or 3D-Secure. "
            "The cardholder is unaware the data has been read."
        ),
        exploit_scenario=(
            "1. Attacker holds a phone with NFC (or Proxmark3) in a public space.\n"
            "2. `emv reader` or `hf 14a apdu -s --apdu 00A4...` extracts PAN + expiry.\n"
            "3. Attacker uses harvested PAN / expiry for online purchases "
            "   at merchants without CVV enforcement or 3DS requirement.\n"
            "4. Victim sees unexpected charges — CNP fraud is blamed on data breach."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_score=5.3,
        cvss_severity="MEDIUM",
        remediation=(
            "Use an RFID-blocking card sleeve or wallet for daily carry. "
            "Request a card with a randomised / tokenised PAN from your bank. "
            "Enable 3D-Secure on all online transactions. "
            "Monitor card statements and enable real-time SMS/push alerts."
        ),
    )


def _check_replay_attack(profile: dict) -> Optional[VulnFinding]:
    if profile.get("mutual_auth") or profile.get("payment_card"):
        return None
    if "LF" in profile.get("family", ""):
        return None
    return VulnFinding(
        vuln_id="RFID-008",
        title="Replay Attack Feasible — No Freshness / Rolling Code Mechanism",
        description=(
            "Without mutual authentication and fresh nonces, responses captured "
            "from legitimate card-reader interactions can be replayed at a later time. "
            "Since the reader cannot verify that a response is 'fresh', "
            "a recorded trace can be fed back to gain access or approve a transaction."
        ),
        exploit_scenario=(
            "1. Attacker places Proxmark3 in sniff mode near a legitimate "
            "   access control reader (`hf 14a sniff`).\n"
            "2. A legitimate cardholder taps — the full exchange is recorded.\n"
            "3. Attacker plays back the captured trace (`hf 14a replay`) "
            "   to the reader when no valid card is nearby.\n"
            "4. Reader, unable to distinguish fresh from stale response, "
            "   grants access."
        ),
        cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        cvss_score=6.8,
        cvss_severity="MEDIUM",
        remediation=(
            "Implement challenge-response authentication using random nonces "
            "generated freshly per transaction by both card and reader. "
            "Deploy AES-based session keys derived per authentication. "
            "Use ISO14443-4 secure messaging with a transaction sequence counter."
        ),
    )


def _check_no_cid(protocol: dict) -> Optional[VulnFinding]:
    if protocol.get("cid_supported") or not protocol:
        return None
    return VulnFinding(
        vuln_id="RFID-010",
        title="No Card ID (CID) Support — Impersonation of Multiple Cards",
        description=(
            "The card does not support ISO14443 Card ID (CID) anti-collision. "
            "Without CID, a multi-card environment cannot reliably isolate "
            "individual cards — a malicious device can masquerade responses "
            "for multiple card identities. This degrades the integrity of "
            "anti-collision loops in dense card environments."
        ),
        exploit_scenario=(
            "1. In a multi-reader environment, attacker emulates multiple card UIDs "
            "   simultaneously using a Proxmark3 in emulation mode.\n"
            "2. Without CID, the reader cannot distinguish between cards — "
            "   attacker can inject responses on behalf of any known UID.\n"
            "3. Access decisions or cafeteria deductions may be attributed to "
            "   the wrong card identity."
        ),
        cvss_vector="CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
        cvss_score=3.9,
        cvss_severity="LOW",
        remediation=(
            "Use ISO14443-4 compliant cards with full CID support. "
            "For existing deployments, restrict the number of cards "
            "active in the RF field simultaneously."
        ),
    )


# ──────────────────────────────────────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_vuln_report(
    profile:  dict,
    uid:      dict,
    protocol: dict,
    timing:   dict,
    emv:      dict,
) -> tuple:
    """
    Run all vulnerability checks and return (findings, security_tier).

    Parameters
    ----------
    profile  : card profile dict from CARD_DATABASE
    uid      : result from analyze_uid()
    protocol : result from analyze_protocol()
    timing   : result from analyze_timing()
    emv      : result from analyze_emv()

    Returns
    -------
    findings      : list[VulnFinding]
    security_tier : str  — "LOW" | "MEDIUM" | "HIGH"
    """
    profile  = profile  or {}
    uid      = uid      or {}
    protocol = protocol or {}
    timing   = timing   or {}
    emv      = emv      or {}

    checks = [
        _check_no_encryption(profile),
        _check_broken_crypto1(profile),
        _check_broken_iclass(profile),
        _check_no_apdu(profile, protocol),
        _check_no_mutual_auth(profile),
        _check_static_uid(uid),
        _check_relay_window(timing, profile),
        _check_emv_skimming(emv),
        _check_replay_attack(profile),
        _check_no_cid(protocol),
    ]

    findings: List[VulnFinding] = [f for f in checks if f is not None]

    # Sort by CVSS score descending
    findings.sort(key=lambda f: f.cvss_score, reverse=True)

    # Determine security tier from highest CVSS
    if not findings:
        tier = "HIGH"
    else:
        top = findings[0].cvss_score
        if top >= 7.0:
            tier = "LOW"
        elif top >= 4.1:
            tier = "MEDIUM"
        else:
            tier = "HIGH"

    return findings, tier
