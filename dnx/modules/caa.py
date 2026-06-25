from __future__ import annotations

import shlex
from dataclasses import dataclass

from dnx.core.resolver import DnxResolver


@dataclass(frozen=True)
class CAARecord:
    flags: str
    tag: str
    value: str
    raw: str

    def to_dict(self) -> dict[str, str]:
        return {"flags": self.flags, "tag": self.tag, "value": self.value, "raw": self.raw}


def _parse_caa(raw: str) -> CAARecord | None:
    try:
        parts = shlex.split(raw)
    except ValueError:
        parts = raw.split()
    if len(parts) < 3:
        return None
    return CAARecord(flags=parts[0], tag=parts[1].lower(), value=" ".join(parts[2:]).strip('"'), raw=raw)


def _status(result) -> str:
    if result.values:
        return "found"
    error_type = str(result.error_type or "").upper()
    if error_type in {"NO_ANSWER", "NXDOMAIN", "OK"}:
        return "not_found"
    return "unknown"


def analyze_caa(domain: str, resolver: DnxResolver) -> dict:
    answer = resolver.resolve(domain, "CAA")
    records = answer.values
    parsed = [item for raw in records if (item := _parse_caa(raw))]
    issue = [r.raw for r in parsed if r.tag == "issue"]
    issuewild = [r.raw for r in parsed if r.tag == "issuewild"]
    iodef = [r.raw for r in parsed if r.tag == "iodef"]
    accounturi = [r.raw for r in parsed if r.tag == "accounturi"]
    status = _status(answer)
    return {
        "checked": True,
        "status": status,
        "found": bool(records),
        "records": records,
        "parsed": [r.to_dict() for r in parsed],
        "issue": issue,
        "issuewild": issuewild,
        "iodef": iodef,
        "accounturi": accounturi,
        "has_wildcard_policy": bool(issuewild),
        "error": answer.error,
        "error_type": answer.error_type,
    }
