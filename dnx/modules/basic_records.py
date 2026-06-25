from __future__ import annotations

from dnx.core.config import ScanConfig
from dnx.core.resolver import DnxResolver


def collect_basic_records(domain: str, resolver: DnxResolver, config: ScanConfig) -> dict:
    records: dict[str, dict] = {}
    batch = resolver.resolve_many([domain], config.record_types, concurrency=min(config.concurrency, len(config.record_types) or 1))
    by_type = batch.get(domain, {})
    for record_type in config.record_types:
        result = by_type.get(record_type) or resolver.resolve(domain, record_type)
        records[record_type] = {
            "name": result.name,
            "values": result.values,
            "error": result.error,
            "ttl": result.ttl,
            "nameserver": result.nameserver,
            "error_type": result.error_type,
            "elapsed_ms": result.elapsed_ms,
            "resolver": result.resolver,
            "tcp": result.tcp,
            "attempts": result.attempts,
        }
    return records
