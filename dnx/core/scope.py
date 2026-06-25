from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


def _load_patterns(path: Path | None) -> list[str]:
    if not path:
        return []
    try:
        return [
            line.strip().lower().strip(".")
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    except OSError:
        return []


@dataclass(frozen=True)
class Scope:
    root_domain: str
    includes: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()

    @classmethod
    def from_config(cls, root_domain: str, config: object) -> "Scope":
        includes = list(getattr(config, "include_subdomains", []) or [])
        excludes = list(getattr(config, "exclude_subdomains", []) or [])
        includes.extend(_load_patterns(getattr(config, "scope_file", None)))
        excludes.extend(_load_patterns(getattr(config, "exclude_file", None)))
        normalized_includes = tuple(sorted(set(_norm(p) for p in includes if p)))
        normalized_excludes = tuple(sorted(set(_norm(p) for p in excludes if p)))
        return cls(root_domain=_norm(root_domain), includes=normalized_includes, excludes=normalized_excludes)

    def in_scope(self, name: str) -> bool:
        clean = _norm(name)
        if clean == self.root_domain or clean.endswith("." + self.root_domain):
            base_match = True
        else:
            base_match = any(_matches(clean, item) for item in self.includes)
        if not base_match:
            return False
        return not any(_matches(clean, item) for item in self.excludes)


def _norm(value: str) -> str:
    value = str(value).strip().lower().strip(".")
    if value.startswith("*."):
        value = value[2:]
    return value


def _matches(name: str, pattern: str) -> bool:
    pattern = _norm(pattern)
    return name == pattern or name.endswith("." + pattern)
