from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import dns.exception
import dns.resolver

from dnx.core.config import ScanConfig


class DNSErrorType(str, Enum):
    OK = "OK"
    NO_ANSWER = "NO_ANSWER"
    NXDOMAIN = "NXDOMAIN"
    NO_NAMESERVERS = "NO_NAMESERVERS"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    ERROR = "ERROR"


@dataclass
class QueryResult:
    record_type: str
    name: str
    values: list[str]
    error: str | None = None
    ttl: int | None = None
    nameserver: str | None = None
    error_type: str = DNSErrorType.OK.value
    elapsed_ms: float | None = None
    resolver: str | None = None
    tcp: bool = False
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return self.error is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": self.record_type,
            "name": self.name,
            "values": self.values,
            "error": self.error,
            "ttl": self.ttl,
            "nameserver": self.nameserver,
            "error_type": self.error_type,
            "elapsed_ms": self.elapsed_ms,
            "resolver": self.resolver,
            "tcp": self.tcp,
            "attempts": self.attempts,
        }


class _RateLimiter:
    def __init__(self, rate_per_second: float = 0.0):
        self.rate = max(0.0, float(rate_per_second or 0.0))
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self) -> None:
        if self.rate <= 0:
            return
        interval = 1.0 / self.rate
        with self._lock:
            now = time.monotonic()
            if now < self._next_at:
                time.sleep(self._next_at - now)
                now = time.monotonic()
            self._next_at = now + interval


class DnxResolver:
    """Caching resolver with retry and optional UDP-to-TCP fallback."""

    def __init__(self, config: ScanConfig, *, resolver_ip: str | None = None):
        self.config = config
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.timeout = config.timeout
        self.resolver.lifetime = config.lifetime
        self._resolver_ip = resolver_ip or config.resolver
        if self._resolver_ip:
            self.resolver.nameservers = [self._resolver_ip]
        self._cache: dict[tuple[str, str, bool], QueryResult] = {}
        self._lock = threading.Lock()
        self._limiter = _RateLimiter(config.rate_limit)

    @property
    def nameservers(self) -> list[str]:
        return list(self.resolver.nameservers)

    def resolve(self, name: str, record_type: str, *, tcp: bool = False, raise_errors: bool = False) -> QueryResult:
        record_type = record_type.upper()
        cache_key = (name.lower().rstrip("."), record_type, tcp)
        with self._lock:
            cached = self._cache.get(cache_key)
        if cached:
            if raise_errors and cached.error:
                raise RuntimeError(cached.error)
            return cached

        attempts = max(1, self.config.retries + 1)
        last_result: QueryResult | None = None
        for attempt in range(1, attempts + 1):
            self._limiter.wait()
            result = self._resolve_once(name, record_type, tcp=tcp, attempts=attempt)
            last_result = result
            if result.ok or result.error_type in {DNSErrorType.NXDOMAIN.value, DNSErrorType.NO_ANSWER.value}:
                break
            if attempt < attempts:
                time.sleep(min(0.25 * attempt, 1.0))

        assert last_result is not None
        # DNS truncation can require TCP. Only retry TCP when the error text suggests
        # truncation; retrying TCP for every timeout doubles scan time in restricted labs.
        if (
            not tcp
            and last_result.error
            and record_type in {"TXT", "DNSKEY", "SOA", "NS", "MX", "CAA"}
            and "trunc" in last_result.error.lower()
        ):
            tcp_result = self.resolve(name, record_type, tcp=True, raise_errors=False)
            if tcp_result.ok:
                last_result = tcp_result

        with self._lock:
            self._cache[cache_key] = last_result
        if raise_errors and last_result.error:
            raise RuntimeError(last_result.error)
        return last_result

    def _resolve_once(self, name: str, record_type: str, *, tcp: bool, attempts: int) -> QueryResult:
        started = time.perf_counter()
        try:
            answer = self.resolver.resolve(name, record_type, tcp=tcp, raise_on_no_answer=True)
            values = [self._clean_rdata(rdata, record_type) for rdata in answer]
            ttl = getattr(answer.rrset, "ttl", None) if answer.rrset else None
            ns = getattr(answer.response, "nameserver", None)
            return QueryResult(
                record_type=record_type,
                name=name,
                values=sorted(set(values)),
                ttl=ttl,
                nameserver=ns,
                resolver=self._resolver_ip or ",".join(self.nameservers),
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                tcp=tcp,
                attempts=attempts,
            )
        except dns.resolver.NoAnswer:
            msg, etype = "No answer", DNSErrorType.NO_ANSWER.value
        except dns.resolver.NXDOMAIN:
            msg, etype = "NXDOMAIN", DNSErrorType.NXDOMAIN.value
        except dns.resolver.NoNameservers as exc:
            text = str(exc)
            if "SERVFAIL" in text.upper():
                msg, etype = "SERVFAIL", DNSErrorType.SERVFAIL.value
            elif "REFUSED" in text.upper():
                msg, etype = "REFUSED", DNSErrorType.REFUSED.value
            else:
                msg, etype = "No nameservers answered", DNSErrorType.NO_NAMESERVERS.value
        except dns.exception.Timeout:
            msg, etype = "Timeout", DNSErrorType.TIMEOUT.value
        except Exception as exc:  # pragma: no cover - defensive network handling
            msg, etype = f"{type(exc).__name__}: {exc}", DNSErrorType.ERROR.value

        return QueryResult(
            record_type=record_type,
            name=name,
            values=[],
            error=msg,
            error_type=etype,
            resolver=self._resolver_ip or ",".join(self.nameservers),
            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
            tcp=tcp,
            attempts=attempts,
        )

    def resolve_values(self, name: str, record_type: str) -> list[str]:
        return self.resolve(name, record_type).values

    def resolve_many(self, names: Iterable[str], record_types: Iterable[str], *, concurrency: int | None = None) -> dict[str, dict[str, QueryResult]]:
        clean_names = list(dict.fromkeys(str(n).strip().lower().strip(".") for n in names if str(n).strip()))
        clean_types = [rtype.upper() for rtype in record_types]
        output: dict[str, dict[str, QueryResult]] = {name: {} for name in clean_names}
        max_workers = max(1, min(concurrency or self.config.concurrency, 256))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self.resolve, name, rtype): (name, rtype)
                for name in clean_names
                for rtype in clean_types
            }
            for future in as_completed(future_map):
                name, rtype = future_map[future]
                try:
                    output[name][rtype] = future.result()
                except Exception as exc:  # pragma: no cover - defensive thread handling
                    output[name][rtype] = QueryResult(record_type=rtype, name=name, values=[], error=str(exc), error_type=DNSErrorType.ERROR.value)
        return output

    @staticmethod
    def _clean_rdata(rdata: Any, record_type: str) -> str:
        text = rdata.to_text().strip()
        if record_type == "TXT":
            text = text.replace('" "', '')
        return text


def load_resolver_ips(path: Path | None) -> list[str]:
    if not path:
        return []
    try:
        return [
            line.split("#", 1)[0].strip()
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.split("#", 1)[0].strip()
        ]
    except OSError:
        return []


class ResolverPool:
    """Small resolver-pool wrapper for comparison and future provider modules."""

    def __init__(self, config: ScanConfig):
        resolver_ips = list(dict.fromkeys([*(load_resolver_ips(config.resolver_file)), *(config.compare_resolvers or [])]))
        if config.resolver:
            resolver_ips.insert(0, config.resolver)
        resolver_ips = list(dict.fromkeys(ip for ip in resolver_ips if ip))
        self.resolvers = [DnxResolver(config, resolver_ip=ip) for ip in resolver_ips] or [DnxResolver(config)]

    def first(self) -> DnxResolver:
        return self.resolvers[0]

    def health(self, domain: str = "example.com") -> list[dict[str, Any]]:
        status = []
        for resolver in self.resolvers:
            started = time.perf_counter()
            answer = resolver.resolve(domain, "A")
            status.append({
                "resolver": resolver.nameservers,
                "ok": answer.ok,
                "error": answer.error,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            })
        return status
