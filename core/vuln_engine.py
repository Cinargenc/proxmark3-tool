"""
vuln_engine.py — Data-driven RFID/NFC Vulnerability Engine

Loads vulnerability definitions from data/vuln_db.json and evaluates
trigger conditions dynamically against card scan data.

Trigger system
--------------
Each DB entry has a `triggers` list and a `trigger_mode` ("any" | "all").

  trigger_mode = "any"  → finding fires if ANY trigger matches
  trigger_mode = "all"  → finding fires only if ALL triggers match

Each trigger is:
  {
    "field": "profile.broken_crypto",  # dot-notation path into context
    "op":    "eq",                     # operator
    "value": true                      # comparison value (optional)
  }

Supported operators
-------------------
  eq            field == value
  neq           field != value
  contains      value in field  (substring or list membership)
  not_contains  value not in field
  in            field in value  (value must be a list)
  not_in        field not in value
  gte           field >= value
  lte           field <= value
  truthy        bool(field) is True
  falsy         not bool(field)
  absent        field missing / None

`exclude_if` is a list of triggers (any matching → skip the finding).

Security Tier
-------------
  LOW    — highest CVSS >= 7.0  (critically weak card)
  MEDIUM — highest CVSS 4.1-6.9 (moderate risk)
  HIGH   — all findings <= 4.0 or no findings (secure)
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, List, Optional

# ──────────────────────────────────────────────────────────────────────────────
#  DB path (relative to this file's parent's parent = project root)
# ──────────────────────────────────────────────────────────────────────────────

_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "vuln_db.json"
)


def _load_db() -> dict:
    with open(_DB_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# Loaded once at import time
_DB: dict = _load_db()


# ──────────────────────────────────────────────────────────────────────────────
#  VulnFinding dataclass  (same interface as before)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnFinding:
    vuln_id:          str
    title:            str
    description:      str
    exploit_scenario: str
    cvss_vector:      str
    cvss_score:       float
    cvss_severity:    str
    remediation:      str
    tags:             List[str] = field(default_factory=list)
    affected_families: List[str] = field(default_factory=list)
    references:       List[str] = field(default_factory=list)

    @classmethod
    def from_db_entry(cls, entry: dict) -> "VulnFinding":
        return cls(
            vuln_id=entry["id"],
            title=entry["title"],
            description=entry["description"],
            exploit_scenario=entry["exploit_scenario"],
            cvss_vector=entry["cvss_vector"],
            cvss_score=float(entry["cvss_score"]),
            cvss_severity=entry["cvss_severity"],
            remediation=entry["remediation"],
            tags=entry.get("tags", []),
            affected_families=entry.get("affected_families", []),
            references=entry.get("references", []),
        )


# ──────────────────────────────────────────────────────────────────────────────
#  Context builder
# ──────────────────────────────────────────────────────────────────────────────

def _build_context(profile: dict, uid: dict, protocol: dict,
                   timing: dict, emv: dict) -> dict:
    """Flatten scan data into a dot-notation accessible context dict."""
    return {
        "profile":  profile  or {},
        "uid":      uid      or {},
        "protocol": protocol or {},
        "timing":   timing   or {},
        "emv":      emv      or {},
    }


def _resolve(context: dict, field_path: str) -> Any:
    """Resolve 'profile.broken_crypto' → context['profile']['broken_crypto']."""
    parts = field_path.split(".")
    val = context
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
    return val


# ──────────────────────────────────────────────────────────────────────────────
#  Trigger evaluator
# ──────────────────────────────────────────────────────────────────────────────

def _eval_trigger(trigger: dict, context: dict) -> bool:
    """Evaluate a single trigger object against the context."""
    field_path = trigger["field"]
    op         = trigger["op"]
    value      = trigger.get("value")            # may be absent for truthy/falsy/absent

    actual = _resolve(context, field_path)

    if op == "eq":
        return actual == value
    if op == "neq":
        return actual != value
    if op == "contains":
        if actual is None:
            return False
        return str(value) in str(actual)
    if op == "not_contains":
        if actual is None:
            return True
        return str(value) not in str(actual)
    if op == "in":
        return actual in value
    if op == "not_in":
        return actual not in value
    if op == "gte":
        return actual is not None and actual >= value
    if op == "lte":
        return actual is not None and actual <= value
    if op == "truthy":
        return bool(actual)
    if op == "falsy":
        return not bool(actual)
    if op == "absent":
        return actual is None
    return False


def _eval_trigger_list(triggers: list, mode: str, context: dict) -> bool:
    """Evaluate a list of triggers with 'any' or 'all' mode."""
    if not triggers:
        return False
    results = [_eval_trigger(t, context) for t in triggers]
    return any(results) if mode == "any" else all(results)


def _is_excluded(entry: dict, context: dict) -> bool:
    """Return True if any exclude_if trigger matches → skip this finding."""
    exclude = entry.get("exclude_if", [])
    return any(_eval_trigger(t, context) for t in exclude)


# ──────────────────────────────────────────────────────────────────────────────
#  CVSS severity helper
# ──────────────────────────────────────────────────────────────────────────────

def _severity(score: float) -> str:
    if score == 0.0:  return "NONE"
    if score < 4.0:   return "LOW"
    if score < 7.0:   return "MEDIUM"
    if score < 9.0:   return "HIGH"
    return "CRITICAL"


# ──────────────────────────────────────────────────────────────────────────────
#  Public API
# ──────────────────────────────────────────────────────────────────────────────

def generate_vuln_report(
    profile:  dict,
    uid:      dict,
    protocol: dict,
    timing:   dict,
    emv:      dict,
) -> tuple[List[VulnFinding], str]:
    """
    Evaluate all DB entries against card data and return (findings, tier).

    Returns
    -------
    findings      : List[VulnFinding]  sorted by CVSS descending
    security_tier : "LOW" | "MEDIUM" | "HIGH"
    """
    context  = _build_context(profile, uid, protocol, timing, emv)
    findings: List[VulnFinding] = []

    for entry in _DB.get("vulnerabilities", []):
        triggers     = entry.get("triggers", [])
        trigger_mode = entry.get("trigger_mode", "any")

        if _is_excluded(entry, context):
            continue
        if _eval_trigger_list(triggers, trigger_mode, context):
            findings.append(VulnFinding.from_db_entry(entry))

    # Sort highest CVSS first
    findings.sort(key=lambda f: f.cvss_score, reverse=True)

    # Security tier
    is_payment_secure = (
        profile.get("payment_card")
        and profile.get("crypto")
        and not profile.get("broken_crypto")
    )

    if not findings:
        tier = "HIGH"
    else:
        top = findings[0].cvss_score
        if is_payment_secure:
            tier = "LOW" if top >= 7.0 else "MEDIUM"
        else:
            if top >= 7.0:   tier = "LOW"
            elif top >= 4.1: tier = "MEDIUM"
            else:            tier = "HIGH"

    return findings, tier


def reload_db() -> None:
    """Reload the vulnerability database from disk (useful for live editing)."""
    global _DB
    _DB = _load_db()


# ──────────────────────────────────────────────────────────────────────────────
#  Query / filter API  (used by vuln_query.py CLI)
# ──────────────────────────────────────────────────────────────────────────────

def list_all_vulns() -> List[dict]:
    """Return all raw vulnerability entries from the DB."""
    return _DB.get("vulnerabilities", [])


def get_vuln_by_id(vuln_id: str) -> Optional[dict]:
    """Return a single vuln entry by ID (e.g. 'RFID-002')."""
    for entry in _DB.get("vulnerabilities", []):
        if entry["id"].upper() == vuln_id.upper():
            return entry
    return None


def search_vulns(
    tag:      Optional[str]   = None,
    family:   Optional[str]   = None,
    min_cvss: Optional[float] = None,
    severity: Optional[str]   = None,
) -> List[dict]:
    """
    Filter vuln DB entries.

    Parameters
    ----------
    tag       : match if tag in entry['tags']          (case-insensitive)
    family    : match if family in entry['affected_families'] or '*'
    min_cvss  : match if cvss_score >= min_cvss
    severity  : match if cvss_severity == severity     (case-insensitive)
    """
    results = []
    for entry in _DB.get("vulnerabilities", []):
        if tag and tag.lower() not in [t.lower() for t in entry.get("tags", [])]:
            continue
        if family:
            fams = entry.get("affected_families", [])
            if "*" not in fams and family not in fams:
                continue
        if min_cvss is not None and float(entry.get("cvss_score", 0)) < min_cvss:
            continue
        if severity and entry.get("cvss_severity", "").upper() != severity.upper():
            continue
        results.append(entry)
    return results


def db_meta() -> dict:
    """Return the _meta section of the DB."""
    return _DB.get("_meta", {})
