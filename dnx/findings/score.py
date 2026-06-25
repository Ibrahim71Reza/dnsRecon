from __future__ import annotations

WEIGHTS = {"CRITICAL": 45, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 0}
CONFIDENCE_MULTIPLIER = {"high": 1.0, "medium": 0.8, "low": 0.5}


def risk_score(findings: list[dict]) -> dict:
    penalty = 0.0
    counts = {key: 0 for key in WEIGHTS}
    categories: dict[str, int] = {}
    seen_ids: set[str] = set()
    for finding in findings:
        sev = str(finding.get("severity", "INFO")).upper()
        counts.setdefault(sev, 0)
        counts[sev] += 1
        categories[finding.get("category", "General")] = categories.get(finding.get("category", "General"), 0) + 1
        raw_fid = finding.get("id") or finding.get("title")
        fid = str(raw_fid) if raw_fid else None
        # Repeated same rule should not linearly destroy the posture score.
        repeat_factor = 0.7 if fid and fid in seen_ids else 1.0
        if fid:
            seen_ids.add(fid)
        confidence = str(finding.get("confidence", "high")).lower()
        penalty += WEIGHTS.get(sev, 0) * CONFIDENCE_MULTIPLIER.get(confidence, 0.8) * repeat_factor
    score = max(0, int(round(100 - penalty)))
    if score >= 90:
        level = "LOW"
    elif score >= 70:
        level = "MODERATE"
    elif score >= 40:
        level = "ELEVATED"
    else:
        level = "HIGH"
    return {"score": score, "level": level, "penalty": round(penalty, 2), "counts": counts, "categories": categories}
