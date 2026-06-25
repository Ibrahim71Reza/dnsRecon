# dnsRecon authorized quickstart

Use these copy-paste commands only on assets you own or are explicitly authorized to test.

## Fast first test

```bash
dnsRecon example.com --fast
```

## Default terminal scan

```bash
dnsRecon example.com
```

## Passive/safe scan

```bash
dnsRecon example.com --mode safe
```

## Optional report files

```bash
dnsRecon example.com --report json,md
```

## OSS adapters

```bash
dnsRecon doctor
dnsRecon example.com --oss --tools subfinder,dnsx
```

## Deep authorized scan

```bash
dnsRecon example.com --ultimate --wordlist wordlists/medium.txt --resolver-file resolvers/public.txt
```

## Pipeline files dnsRecon can write when `--report assets` is used

- `reports/example.com-subdomains.txt`
- `reports/example.com-verified-subdomains.txt`
- `reports/example.com-active-subdomains.txt`
- `reports/example.com-ips.txt`
- `reports/example.com-live-urls.txt`
- `reports/example.com-nuclei-targets.txt`
- `reports/example.com-takeover-candidates.csv`
