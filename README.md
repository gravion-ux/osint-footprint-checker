![osint-footprint-checker banner](assets/banner.svg)

# osint-footprint-checker

Scores the public footprint of an asset **you own** — security.txt,
security headers, SPF/DMARC, dangling CNAMEs and TLS posture — from a JSON
snapshot, and prints the fix for every finding.

Applied coursework: the same public signals an OSINT analyst reads about a
target are the signals you should audit on your own assets first.
Snapshot-based and offline; it performs no probing of third-party systems.

## Install

```bash
pip install -e .
```

Requires Python 3.11+.

## Usage

```bash
osint-footprint-checker snapshot.json
osint-footprint-checker snapshot.json --format json
```

Snapshot shape: `security_txt` (bool), `headers` (map), `dns`
(`spf`, `dmarc`, optional `dangling_cname`), `tls` (`versions`,
`days_to_expiry`).

## Tests

```bash
pytest
```

## License

MIT
