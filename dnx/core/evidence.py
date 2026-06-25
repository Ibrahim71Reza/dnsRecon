from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class Evidence:
    """Structured proof attached to a finding or discovered asset."""

    kind: str
    name: str
    value: Any
    source: str = "dnx"
    confidence: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    confidence: str = "medium"
    category: str = "General"
    affected_assets: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    evidence_items: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_items"] = [item.to_dict() for item in self.evidence_items]
        return data
