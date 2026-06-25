# dnsRecon v1.x

Clean first public release.

## Main decisions

- Renamed project version to `1.x` to avoid over-claiming maturity.
- Kept terminal-first output as the default source of truth.
- Kept reports optional through `--report`.
- Kept optional OSS adapters without making external tools required.

## Fixes from pre-release testing

- Added `dnsRecon doctor` environment check.
- Added `--fast` for quick DNS-only scans.
- Reduced default timeout/retry posture.
- Parallelized passive public-source fetching.
- Replaced blocking external-tool stdout polling with hard `communicate(timeout=...)` execution.
- Reduced default external-tool timeout to 25 seconds.
- Made Amass manual-only in auto mode because it can run for a long time.
- Added module timing output to the terminal report.
- Added terminal spinner while scan modules run.

## Command naming

- Primary command is now `dnsRecon`.
- `dnx` remains as a temporary backward-compatible alias.

## Validation

- Unit tests pass.
- `python -m compileall -q dnx` passes.
- `dnsRecon --version` returns the installed v1 version.
- `dnsRecon doctor` prints optional tool availability.


## v1.0.1 - Cleanup and speed patch

- Cleaned remaining `DNX` wording from user-facing terminal messages and recommendations.
- `--profile quick` now avoids slow passive APIs unless `--mode passive` is explicitly selected.
- Quick profile skips wildcard and service-record sweeps to prevent unexpected long scans.
- Quick/fast runs limit reverse DNS to apex addresses instead of all nameserver glue addresses.
- `--oss --tools subfinder,dnsx` now fails immediately if both binaries are missing instead of running a long native fallback scan.
- Added clearer warning when `--oss --tools auto` has no auto-safe adapters installed.
- Default CLI profile is now `quick` with lower timeout/retry defaults.
- Quick profile skips default wordlist brute-force unless `--wordlist` is supplied.
- WHOIS/RDAP is now opt-in with `--whois`; `--no-whois` remains accepted.
- Default resolver is now `1.1.1.1` for predictable quick scans; users can override it.
- Quick profile now uses a smaller essential record set and reduced DKIM selector list.
- Independent DNS modules now run concurrently to reduce timeout stacking.
- Quick profile skips DKIM selector brute-checks; balanced/deep still include them.
- Quick profile now skips slower advanced mail DNS checks and suppresses their missing-policy findings.
- Passive-source missing-data finding is now shown only when passive discovery was enabled.


## v1.0.3 - Final v1 accuracy-safe release

- Finalized v1 package name and command behavior as `dnsRecon`.
- Timeout and transient DNS failures are now classified as `unknown`, not as confirmed missing records.
- Missing SPF, DMARC, CAA, DNSSEC, NS, SOA, and MX findings are raised only when evidence is conclusive.
- Added an Evidence Reliability terminal section when DNS evidence is inconclusive.
- Quick/default scans now use a 2-second lifetime by default, skip WHOIS/RDAP, skip AXFR, and stay terminal responsive.
- Quick/default mode avoids MTA-STS/TLS-RPT/BIMI/DKIM negative sweeps and suppresses skipped-check findings.
- Nameserver and DNS-health checks no longer create high-severity findings from resolver timeouts.
- CAA and DNSSEC modules now keep resolver error metadata in report output.
- Operator notes now clearly show fast, accurate, deep, and report commands.

Validation:

- `python -m compileall -q dnx` passes.
- `python -m pytest -q` returns 18 passed.
- `dnsRecon --version` returns `dnsRecon v1.0.3`.
- `dnsRecon doctor` works.
- Missing requested OSS tools exit immediately with a clear message.
- Quick JSON smoke test confirms unknown evidence is not scored as confirmed missing/misconfigured.
