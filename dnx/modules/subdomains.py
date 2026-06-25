from __future__ import annotations

from pathlib import Path

from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver
from dnx.core.scope import Scope
from dnx.modules.ct_logs import fetch_passive_subdomains
from dnx.modules.permutations import generate_permutations

DEFAULT_WORDS = [
    "www", "mail", "smtp", "imap", "pop", "webmail", "admin", "portal", "app", "api",
    "dev", "test", "stage", "staging", "beta", "cdn", "static", "assets", "vpn", "remote",
    "ns1", "ns2", "mx", "blog", "shop", "support", "docs", "status", "sso", "auth",
    "login", "dashboard", "cpanel", "whm", "ftp", "files", "download", "uploads", "media",
    "m", "mobile", "old", "new", "secure", "gw", "gateway", "intranet", "office", "cloud",
    "grafana", "kibana", "jenkins", "git", "gitlab", "jira", "confluence", "vpn2", "api-dev",
    "api-stage", "uat", "preprod", "prod", "origin", "internal", "admin-dev", "graphql",
]


def load_words(path: Path | None) -> list[str]:
    if not path:
        return DEFAULT_WORDS
    try:
        words = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip().lower()
            if value and not value.startswith("#"):
                words.append(value.split()[0].strip("."))
        return sorted(set(words)) or DEFAULT_WORDS
    except OSError:
        return DEFAULT_WORDS


def resolve_subdomain(name: str, resolver: DnxResolver) -> dict:
    results = resolver.resolve_many([name], ["A", "AAAA", "CNAME"], concurrency=3).get(name, {})
    a = results.get("A", resolver.resolve(name, "A")).values
    aaaa = results.get("AAAA", resolver.resolve(name, "AAAA")).values
    cname = results.get("CNAME", resolver.resolve(name, "CNAME")).values
    values = sorted(set(a + aaaa))
    return {
        "name": name,
        "addresses": values,
        "cname": cname,
        "resolved": bool(values or cname),
        "evidence": {rtype: result.to_dict() for rtype, result in results.items()},
    }


def _resolve_many_subdomains(names: list[str], resolver: DnxResolver, config: ScanConfig) -> list[dict]:
    if not names:
        return []
    results = resolver.resolve_many(names, ["A", "AAAA", "CNAME"], concurrency=config.concurrency)
    out = []
    for name, by_type in results.items():
        a = by_type.get("A")
        aaaa = by_type.get("AAAA")
        cname = by_type.get("CNAME")
        addresses = sorted(set((a.values if a else []) + (aaaa.values if aaaa else [])))
        cnames = cname.values if cname else []
        out.append({
            "name": name,
            "addresses": addresses,
            "cname": cnames,
            "resolved": bool(addresses or cnames),
            "evidence": {rtype: result.to_dict() for rtype, result in by_type.items()},
        })
    return out


def _wildcard_match(values: list[str], wildcard: dict | None) -> bool:
    wildcard_values = set((wildcard or {}).get("wildcard_values", []))
    return bool(wildcard_values and values and set(values).issubset(wildcard_values))


def _candidate_words(domain: str, config: ScanConfig, scope: Scope) -> list[str]:
    words = load_words(config.wordlist)
    names = [f"{word}.{domain}".lower() for word in words]
    return [name for name in names if scope.in_scope(name)]


def discover_subdomains(domain: str, resolver: DnxResolver, config: ScanConfig, wildcard: dict | None = None) -> dict:
    scope = Scope.from_config(domain, config)
    passive_results = {"source": "multi-passive", "sources": [], "subdomains": [], "source_map": {}, "error": "disabled"}
    if config.passive and config.ct_logs:
        passive_results = fetch_passive_subdomains(domain, timeout=config.timeout, retries=config.retries)

    active: list[dict] = []
    queries_used = 0
    if config.active and config.brute_force:
        candidates = _candidate_words(domain, config, scope)
        candidates = candidates[: max(0, config.max_dns_queries)]
        queries_used += len(candidates) * 3
        active = _resolve_many_subdomains(candidates, resolver, config)
        for item in active:
            item["wildcard_match"] = _wildcard_match(item["addresses"], wildcard)
            item["sources"] = ["wordlist"]

    all_names = {name for name in passive_results.get("subdomains", []) if scope.in_scope(name)}
    all_names.update(item["name"] for item in active if item.get("resolved") and not item.get("wildcard_match") and scope.in_scope(item["name"]))

    source_map: dict[str, set[str]] = {
        name: set(srcs) for name, srcs in passive_results.get("source_map", {}).items() if scope.in_scope(name)
    }
    for item in active:
        if item.get("resolved") and not item.get("wildcard_match") and scope.in_scope(item["name"]):
            source_map.setdefault(item["name"], set()).add("wordlist")

    permutation_results: list[dict] = []
    if config.active and config.permutations and all_names:
        remaining = max(0, config.max_dns_queries - queries_used)
        generated = generate_permutations(sorted(all_names), domain, limit=max(0, remaining // 3))
        generated = [name for name in generated if scope.in_scope(name) and name not in all_names]
        queries_used += len(generated) * 3
        permutation_results = _resolve_many_subdomains(generated, resolver, config)
        for item in permutation_results:
            item["wildcard_match"] = _wildcard_match(item["addresses"], wildcard)
            item["sources"] = ["permutation"]
            if item.get("resolved") and not item.get("wildcard_match"):
                all_names.add(item["name"])
                source_map.setdefault(item["name"], set()).add("permutation")

    recursive_results: list[dict] = []
    if config.active and config.recursive_depth > 0 and all_names:
        # Controlled recursive expansion: try the most useful service labels under
        # already discovered branches, bounded by the same DNS query budget.
        parents = sorted(all_names)
        words = load_words(config.wordlist)[:50]
        seen_candidates: set[str] = set()
        for _depth in range(1, max(0, config.recursive_depth) + 1):
            remaining = max(0, config.max_dns_queries - queries_used)
            if remaining < 3:
                break
            candidates: list[str] = []
            for parent in parents:
                for word in words:
                    candidate = f"{word}.{parent}".lower()
                    if candidate not in all_names and candidate not in seen_candidates and scope.in_scope(candidate):
                        seen_candidates.add(candidate)
                        candidates.append(candidate)
                    if len(candidates) >= remaining // 3:
                        break
                if len(candidates) >= remaining // 3:
                    break
            if not candidates:
                break
            queries_used += len(candidates) * 3
            batch = _resolve_many_subdomains(candidates, resolver, config)
            new_parents: list[str] = []
            for item in batch:
                item["wildcard_match"] = _wildcard_match(item["addresses"], wildcard)
                item["sources"] = [f"recursive-depth-{_depth}"]
                if item.get("resolved") and not item.get("wildcard_match"):
                    all_names.add(item["name"])
                    new_parents.append(item["name"])
                    source_map.setdefault(item["name"], set()).add(f"recursive-depth-{_depth}")
            recursive_results.extend(batch)
            parents = new_parents
            if not parents:
                break

    verified = []
    if config.verify_subdomains:
        to_verify = sorted(all_names)[: max(0, config.max_verify)]
        verified = _resolve_many_subdomains(to_verify, resolver, config)
        filtered = []
        for resolved in verified:
            resolved["wildcard_match"] = _wildcard_match(resolved["addresses"], wildcard)
            resolved["sources"] = sorted(source_map.get(resolved["name"], []))
            if resolved["resolved"] and not resolved.get("wildcard_match"):
                filtered.append(resolved)
        verified = filtered

    return {
        "passive": passive_results,
        "active": active,
        "permutations": permutation_results,
        "recursive": recursive_results,
        "unique_subdomains": sorted(all_names),
        "count": len(all_names),
        "source_map": {name: sorted(srcs) for name, srcs in sorted(source_map.items())},
        "verified_subdomains": verified,
        "verified_count": len(verified),
        "verification_enabled": config.verify_subdomains,
        "verification_limit": config.max_verify,
        "recursive_depth": config.recursive_depth,
        "permutation_enabled": config.permutations,
        "dns_queries_budget": config.max_dns_queries,
        "dns_queries_estimated": queries_used,
    }
