## FOR GETTING LAST VERSION OF DATADOME SOLVER DM ME [@yallc](https://t.me/yallc)

# DataDome V5.7.0 Solver

A Go library and CLI tool for generating DataDome browser fingerprints and obtaining valid cookies. Uses Chrome TLS fingerprinting via [uTLS](https://github.com/refraction-networking/utls) to bypass TLS-based bot detection.

**Author:** [yallc](https://t.me/yallc)

---

## Features

- Chrome 149 fingerprint generation (~180 signals)
- Encrypted jspl payload construction (XOR + dual PRNG keystreams + custom base64)
- Chrome TLS fingerprint impersonation via uTLS (JA3/JA4 match)
- HTTP/2 transport with proxy support (HTTP CONNECT / SOCKS)
- Single-phase and two-phase solve modes
- Cookie verification against target site (uses same Chrome TLS)
- XOR integrity checksums (sgb/sgd/sgc) computed correctly inline

---

## Changelog: v5.6.6 → v5.7.0

### Chrome Version

| | v5.6.6 | v5.7.0 |
|---|--------|--------|
| Chrome | 148 | 149 |
| UA | `Chrome/148.0.7778.217` | `Chrome/149.0.0.0` |
| Full version | `148.0.7778.217` | `149.0.7827.53` |

### Brand String Format Change

```
v5.6.6: "Not/A)Brand";v="8"
v5.7.0: "Not)A;Brand";v="24"
```

This affects `sec-ch-ua`, `sec-ch-ua-full-version-list`, and the `nhi` signal.

### Signals Removed (5)

| Signal | Description |
|--------|-------------|
| `cfpjs` | Canvas fingerprint JS hash |
| `tbce` | Tab close event listener |
| `rce` | Reduced color encoding |
| `dfps` | Device font pixel size |
| `htmlcs` | HTML charset detection |

### Signals Added (4)

| Signal | Description |
|--------|-------------|
| `wwlrv` | WebWorker language revision |
| `exp8` | Experimental flag 8 |
| `cdhf` | CDH fingerprint flag |
| `bbs3` | Built-in browser storage v3 |

### Signal Renamed (1)

| Old Name | New Name | Description |
|----------|----------|-------------|
| `vcmku` | `vcmkuts` | VP9/MKV codec TS flag |

### Navigation Timing Keys Removed (5)

| Signal | Description |
|--------|-------------|
| `nt_unt` | Unload timing |
| `nt_ddi` | DOM domain interactive |
| `nt_dcl` | DOM content loaded |
| `nt_rsd` | Response start delta |
| `nt_dce` | DOM content end |

### Feature Flags Removed (3)

| Signal | Description |
|--------|-------------|
| `mmapi` | MediaMetadata API |
| `jset2` | JS execution time v2 |
| `wcsm` | WebCrypto subtle methods |

### Browser Check APIs Added (5)

New APIs checked in `bchk` fingerprint:

| API | Present in Chrome 149 |
|-----|----------------------|
| `DetachedViewControlEvent` | No |
| `SiteBoundCredential` | No |
| `WebSocketStream` | Yes |
| `DisplayNames` | No |
| `SVGDiscardElement` | Yes |

### Header Changes

| Header | v5.6.6 | v5.7.0 |
|--------|--------|--------|
| `sec-fetch-site` (POST) | `same-origin` | `cross-site` |

### TLS Fingerprint Fix

v5.7.0 solver uses `utls.HelloChrome_Auto` for **both** the POST (cookie creation) and GET (cookie verification) requests. This ensures the TLS fingerprint (JA3/JA4) matches Chrome consistently. Previously, using Go's default `net/http` for GET requests caused cookie rejection (403) because DataDome binds cookie trust to the TLS fingerprint used during creation.

---

## Install

```bash
go install github.com/L0ed0/datadome-solver/cmd/solver@latest
```

Or build from source:

```bash
git clone https://github.com/L0ed0/datadome-solver.git
cd datadome-solver
go build -o solver ./cmd/solver/
```

---

## CLI Usage

### Solve and get cookie

```bash
solver -site "https://example.com" -key "YOUR_DDK_KEY" -solve
```

### Solve and verify cookie works

```bash
solver -site "https://example.com" -key "YOUR_DDK_KEY" -verify
```

### Two-phase solve (initial + behavioral)

```bash
solver -site "https://example.com" -key "YOUR_DDK_KEY" -two-phase -delay 5
```

### With proxy

```bash
solver -site "https://example.com" -key "YOUR_DDK_KEY" -verify -proxy "http://user:pass@proxy:8080"
```

### Dump raw payload as JSON

```bash
solver -site "https://example.com" -output payload.json
```

### Print encrypted jspl

```bash
solver -site "https://example.com" -key "YOUR_DDK_KEY" -encrypt
```

---

## Library Usage

```go
package main

import (
    "context"
    "fmt"
    "github.com/L0ed0/datadome-solver/pkg/solver"
)

func main() {
    client, err := solver.New("https://example.com",
        solver.WithDDJSKey("YOUR_DDK_KEY"),
        solver.WithProxy("http://proxy:8080"), // optional
    )
    if err != nil {
        panic(err)
    }

    // Single-phase solve
    result, err := client.Solve(context.Background())
    if err != nil {
        panic(err)
    }
    fmt.Println("Cookie:", result.Cookie)

    // Verify cookie works
    status, body, err := client.Verify(context.Background(), result.Cookie)
    fmt.Printf("Status: %d, Body length: %d\n", status, len(body))
}
```

---

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-site` | | Target site URL (required) |
| `-key` | | DataDome JS key (ddk) |
| `-solve` | `false` | Solve and print cookie |
| `-verify` | `false` | Solve then verify with GET |
| `-two-phase` | `false` | Two-phase solve |
| `-delay` | `10` | Delay between phases (seconds) |
| `-proxy` | | HTTP/SOCKS proxy URL |
| `-profile` | `chrome_win10` | Browser profile |
| `-cid` | | Existing CID value |
| `-bpc` | `1` | BPC value |
| `-jstype` | `ch` | jsType field |
| `-event-counters` | `[]` | Event counters JSON |
| `-encrypt` | `false` | Print encrypted jspl only |
| `-output` | | Write payload JSON to file |
| `-seed` | `0` | PRNG seed (0 = random) |

---

## Architecture

```
cmd/solver/          CLI entrypoint
pkg/solver/
  client.go          Client, Solve, SolveTwoPhase, Verify
  transport.go       Chrome TLS transport (uTLS + HTTP/2)
internal/
  builder/
    builder.go       Signal payload assembly
    generators.go    Fingerprint generators (bchk, nav timing, checksums)
    profiles.go      Browser profiles (Chrome 149 / Win10)
  crypto/
    crypto.go        jspl encryption (XOR + PRNG + custom base64)
```

---

## How It Works

1. **Build fingerprint** - Generates ~180 browser signals matching Chrome 149 on Windows 10 (screen, WebGL, plugins, codecs, nav timing, error stacks, etc.)
2. **Compute checksums** - Calculates XOR integrity checksums (sgb/sgd/sgc) inline during payload construction, ensuring internal consistency
3. **Encrypt** - Encodes signals as JSON, XORs with two PRNG keystreams (seeded by DDK + CID + timestamp), encodes with custom base64
4. **POST** - Sends encrypted jspl to `api-js.datadome.co/js/` with Chrome headers over a Chrome-impersonated TLS connection (uTLS)
5. **Cookie** - Server returns a `datadome=...` cookie if fingerprint passes validation
6. **Verify** - Cookie is used for requests to the target site over the same Chrome TLS transport

---

## License

MIT
