from __future__ import annotations

import random
import string
from collections import Counter

from dnx.core.resolver import DnxResolver


def detect_wildcard(domain: str, resolver: DnxResolver, attempts: int = 7) -> dict:
    attempts = max(3, attempts)
    tests = []
    resolved_sets: list[tuple[str, ...]] = []
    for _ in range(attempts):
        label = "dnx-" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(18))
        name = f"{label}.{domain}"
        results = resolver.resolve_many([name], ["A", "AAAA", "CNAME"], concurrency=3).get(name, {})
        a = results.get("A").values if results.get("A") else []
        aaaa = results.get("AAAA").values if results.get("AAAA") else []
        cname = results.get("CNAME").values if results.get("CNAME") else []
        values = sorted(set(a + aaaa + cname))
        tests.append({"name": name, "values": values, "evidence": {rtype: item.to_dict() for rtype, item in results.items()}})
        if values:
            resolved_sets.append(tuple(values))
    counter = Counter(resolved_sets)
    common, count = counter.most_common(1)[0] if counter else ((), 0)
    detected = bool(common) and count >= max(2, attempts // 2)
    return {
        "detected": detected,
        "tests": tests,
        "wildcard_values": list(common) if detected else sorted(set(v for values in resolved_sets for v in values)),
        "confidence": "high" if detected and count >= attempts - 1 else "medium" if detected else "low",
        "matching_tests": count,
        "attempts": attempts,
    }
