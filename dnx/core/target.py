from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$"
)


@dataclass(frozen=True)
class Target:
    """Normalized target domain."""

    original: str
    domain: str

    @property
    def report_name(self) -> str:
        return self.domain.replace("/", "_").replace(":", "_")


def normalize_target(value: str) -> Target:
    """Normalize a user-supplied target into an ASCII domain name."""
    if not value or not value.strip():
        raise ValueError("Target domain is required.")

    original = value.strip()
    candidate = original

    if "://" in candidate:
        parsed = urlparse(candidate)
        candidate = parsed.hostname or ""
    else:
        candidate = candidate.split("/", 1)[0]
        candidate = candidate.split("?", 1)[0]
        candidate = candidate.split("#", 1)[0]
        if "@" in candidate:
            candidate = candidate.rsplit("@", 1)[-1]
        if ":" in candidate and not candidate.count(":") > 1:
            candidate = candidate.split(":", 1)[0]

    candidate = candidate.strip().strip(".").lower()
    if candidate.startswith("*."):
        candidate = candidate[2:]

    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid internationalized domain: {original}") from exc

    if not DOMAIN_RE.match(ascii_domain + "."):
        raise ValueError(f"Invalid domain name: {original}")

    return Target(original=original, domain=ascii_domain)
