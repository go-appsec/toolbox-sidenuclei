# go-appsec/toolbox-sidenuclei

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/toolbox-sidenuclei/blob/main/LICENSE)
[![Tests - Main Push](https://github.com/go-appsec/toolbox-sidenuclei/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/toolbox-sidenuclei/actions/workflows/tests-main.yml)
[![Vibe-Scale 2.0(V2|U0|T1): Significant AI, partial testing](https://img.shields.io/badge/Vibe--Scale%202.0(V2%7CU0%7CT1)-Significant%20AI%2C%20partial%20testing-2ca02c)](https://github.com/vibesdk/vibe-scale/blob/main/scale/vibe-2.md#v2-u0-t1-score-20--significant-ai-partial-testing)

**Automated [Nuclei](https://github.com/projectdiscovery/nuclei) scanning for [go-appsec/toolbox](https://github.com/go-appsec/toolbox).**

Extra coverage for free. While you and your agent explore an app through sectool, `sidenuclei` quietly scans every endpoint you touch and files what it finds back as notes - so known vulnerabilities and injection points surface on their own, alongside the flows you're already generating.

It scans each endpoint with the real request you captured - method, parameters, cookies, and body - so tests exercise the app the way you actually used it, authenticated sessions included. Findings land as `finding` notes linked to the flow that triggered them, ready for the agent to pick up at review time.

## Getting Started

`sidenuclei` attaches to a running sectool session. If you don't have one yet, start with [go-appsec/toolbox](https://github.com/go-appsec/toolbox); sectool just needs to be started with `--notes` so findings have somewhere to land.

### 1. Install

```bash
go install github.com/go-appsec/toolbox-sidenuclei/sidenuclei@latest
```

The scanner is self-contained - no separate Nuclei install, and templates download automatically on first run.

### 2. Start sectool with notes enabled

```bash
sectool mcp --notes
```

### 3. Attach the scanner

```bash
sidenuclei
```

That's it. Browse and test as you normally would - `sidenuclei` finds the running sectool, scans new endpoints as they appear, and keeps pace behind your live traffic. Detection findings accumulate as notes; the agent surfaces them with `notes_list` at review time.

## Expanding coverage

Coverage is a set of categories you turn on and off. A safe default set runs out of the box; you opt into the more aggressive checks as a session warrants.

**On by default** (disable any with `--disable-<name>`):

| Flag | Covers |
|------|--------|
| `--disable-cve` | known CVEs |
| `--disable-exposures` | exposed panels, files, and other exposures |
| `--disable-misconfig` | misconfigurations |
| `--disable-tech` | technology / version fingerprinting |
| `--disable-ssrf` | server-side request forgery (out-of-band) |
| `--disable-redirect` | open redirects |

**Opt-in** (off by default; these send active injection payloads):

| Flag | Covers |
|------|--------|
| `--sqli` | SQL injection |
| `--xss` | cross-site scripting |
| `--cmdi` | command injection |
| `--ssti` | server-side template injection |
| `--xxe` | XML external entity |
| `--crlf` | CRLF injection |
| `--cve-injection` | known-CVE injection checks |

Enabling any injection class is independent - `--sqli` turns on SQLi and nothing else.

## Configuration

Other common flags (run `sidenuclei --help` for the full set):

| Flag | Default | Purpose |
|------|---------|---------|
| `--fuzz-medium` | (default) | payload volume; also `--fuzz-low` / `--fuzz-high` |
| `--fuzz-methods` | `GET,POST` | HTTP methods eligible for fuzzing |
| `--fuzz-scope` / `--fuzz-out-scope` | (none) | URL patterns to keep fuzzing in or out of bounds |
| `--oast-servers` | our servers | out-of-band callback servers (empty disables OAST) |
| `--scan-timeout` | `5m` | per-endpoint time budget |

Out-of-band testing (for blind SSRF and similar) is enabled by default against our OAST servers and needs outbound network access; clear `--oast-servers` to turn it off.

## A note on active testing

The opt-in injection classes replay your real, often authenticated, requests with attack payloads against a live application. Treat them like any hands-on testing: point them at systems you're authorized to test, enable classes deliberately, and use `--fuzz-scope` / `--fuzz-out-scope` to bound which URLs are fuzzed.
