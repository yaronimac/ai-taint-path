"""Threat-intelligence enrichment: how easy is each CVE to use as a foothold?

The order of evidence is: CISA KEV (exploited in the wild) beats EPSS
(probability of exploitation in the next 30 days), which beats CVSS (how bad
it would be). CVSS alone never makes a CVE look easy: it measures impact, not
likelihood. EPSS is optional; without it the engine falls back to CVSS bands
and says so.
"""

from __future__ import annotations

from ..model import Feeds, Finding

EASE_KEV = 0.9
EASE_EPSS_HIGH, EASE_EPSS_LOW, EPSS_THRESHOLD = 0.6, 0.3, 0.1
EASE_CVSS_CRITICAL, EASE_CVSS_HIGH, EASE_CVSS_OTHER = 0.4, 0.3, 0.15


def parse_vector(vector: str | None) -> dict[str, str]:
    """CVSS v3.x or v4.0 vector -> {AV, UI, C, I, A}."""
    if not vector:
        return {}
    metrics = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    return {
        "AV": metrics.get("AV"), "UI": metrics.get("UI"),
        "C": metrics.get("C") or metrics.get("VC"), "I": metrics.get("I") or metrics.get("VI"),
        "A": metrics.get("A") or metrics.get("VA"),
    }


def cve_intel(cve: str, feeds: Feeds) -> dict:
    rec = feeds.records.get(cve, {})
    kev = feeds.kev.get(cve) or {}
    return {
        "kev": bool(kev),
        "kev_date_added": kev.get("dateAdded"),
        "kev_due_date": kev.get("dueDate"),
        "kev_required_action": kev.get("requiredAction"),
        "ransomware_use": kev.get("knownRansomwareCampaignUse") == "Known" or None,
        "epss": feeds.epss.get(cve),
        "cvss": rec.get("cvss"),
        "cvss_vector": rec.get("vector"),
        "cvss_severity": (rec.get("severity") or "").lower() or None,
        "cve_title": kev.get("vulnerabilityName") or _short(rec.get("title")),
    }


def _short(title: str | None, limit: int = 110) -> str | None:
    if not title:
        return None
    flat = " ".join(title.split("\n\n")[0].split())
    return flat if len(flat) <= limit else flat[:limit].rsplit(" ", 1)[0] + "…"


def cve_ease(intel: dict) -> tuple[float, str]:
    if intel.get("kev"):
        return EASE_KEV, "on the CISA KEV list (exploited in the wild)"
    epss = intel.get("epss")
    if epss is not None:
        if epss >= EPSS_THRESHOLD:
            return EASE_EPSS_HIGH, f"EPSS {epss:.2f}: likely to be exploited soon"
        return EASE_EPSS_LOW, f"EPSS {epss:.2f}: exploitation unlikely soon"
    cvss = intel.get("cvss")
    if cvss is None:
        return EASE_CVSS_OTHER, "no KEV entry, EPSS score or CVSS score"
    band = EASE_CVSS_CRITICAL if cvss >= 9 else EASE_CVSS_HIGH if cvss >= 7 else EASE_CVSS_OTHER
    return band, f"CVSS {cvss:g}, not known to be exploited (no EPSS score available)"


def foothold_capable(intel: dict) -> tuple[bool, str]:
    """Can this CVE give an attacker control, or only knock something over?"""
    v = parse_vector(intel.get("cvss_vector"))
    if v.get("C") == "N" and v.get("I") == "N":
        return False, "availability impact only (denial of service), no foothold"
    if v.get("AV") in ("L", "P") and not intel.get("kev"):
        return False, "needs local or physical access"
    return True, ""


def severity_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "medium"
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"


def enrich(findings: list[Finding], feeds: Feeds) -> None:
    """Fill in intel, title, severity, ease and the foothold tag for CVE findings, in place."""
    for f in findings:
        if not f.cve:
            continue
        intel = cve_intel(f.cve, feeds)
        f.intel = {k: v for k, v in intel.items() if v is not None}
        f.title = f.title or f"{f.cve}: {intel['cve_title'] or 'vulnerability'}"
        f.severity = f.severity if f.rule else (intel["cvss_severity"] or severity_from_cvss(intel["cvss"]))
        f.remediation = f.remediation or intel["kev_required_action"] or "Apply the vendor's fix."
        if not f.is_open:
            continue
        capable, why_not = foothold_capable(intel)
        if capable:
            f.ease, f.intel["ease_reason"] = cve_ease(intel)
            if "foothold" not in f.tags:
                f.tags.append("foothold")
        else:
            f.ease = None
            f.intel["not_a_foothold"] = why_not
            f.tags = [t for t in f.tags if t != "foothold"]
