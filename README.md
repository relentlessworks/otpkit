# otpkit

Agentic-first TOTP and HOTP generation and verification service. Generate time-based OTP codes (RFC 6238), counter-based OTP codes (RFC 4226), generate otpauth:// URIs for authenticator apps, verify OTP codes, and generate secret keys. Plain text API, agent-driven, single Go binary. No database needed — pure stateless computation.

## Quick Start

```bash
# Build
make build

# Run (defaults to :8470)
./otpkit

# Generate a TOTP code
curl "http://localhost:8470/totp?secret=JBSWY3DPEHPK3PXP"
# code=123456 digits=6 period=30 algorithm=SHA1 remaining=25

# Verify a TOTP code
curl "http://localhost:8470/totp/verify?secret=JBSWY3DPEHPK3PXP&code=123456"
# valid=true window=1

# Generate a new secret
curl "http://localhost:8470/secret"
# secret=KRSXG5BAIFAUKVTFNFGGYZLTNE bytes=20

# Generate an otpauth:// URI for authenticator app setup
curl "http://localhost:8470/uri?secret=JBSWY3DPEHPK3PXP&label=alice&issuer=ACME"
# uri=otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30 type=totp label=alice
```

## API Reference

### TOTP (Time-based OTP — RFC 6238)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/totp` | GET/POST | Generate a TOTP code |
| `/totp/verify` | GET/POST | Verify a TOTP code |
| `/totp/remaining` | GET | Seconds remaining in current window |
| `/totp/progress` | GET | Progress percentage of current window |

**Parameters:** `secret` (base32, required), `digits` (1-10, default 6), `period` (seconds, default 30), `algorithm` (SHA1/SHA256/SHA512, default SHA1), `time` (Unix timestamp, default now), `window` (verify look-ahead/behind, default 1)

### HOTP (Counter-based OTP — RFC 4226)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/hotp` | GET/POST | Generate an HOTP code |
| `/hotp/verify` | GET/POST | Verify an HOTP code |

**Parameters:** `secret` (base32, required), `counter` (uint64, default 0), `digits` (1-10, default 6), `algorithm` (SHA1/SHA256/SHA512, default SHA1), `window` (verify look-ahead, default 0)

### Secret Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/secret` | GET/POST | Generate a random base32 secret |
| `/secret/hex` | GET/POST | Convert base32 secret to hex |
| `/hex/secret` | GET/POST | Convert hex to base32 secret |

### OTP URI

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/uri` | GET/POST | Generate otpauth:// URI for authenticator apps |

**Parameters:** `secret` (required), `label` (default "user"), `issuer`, `type` (totp/hotp, default totp), `digits`, `period`, `algorithm`, `counter` (for hotp)

### MCP

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST | MCP JSON-RPC 2.0 endpoint (10 tools) |

### Self-Documentation

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/help` | GET | One-page operating manual |
| `/.well-known/agent.md` | GET | Same as /help |

## Output Format

- **Plain text** (default): space-separated `key=value` pairs, one record per line
- **JSON**: send `Accept: application/json` header or add `?format=json`
- **Errors**: `error: message | hint: what to do next`

## Configuration

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `-addr` | `OTPKIT_ADDR` | `:8470` | Listen address |
| `-no-auth` | `OTPKIT_NO_AUTH` | `false` | Disable auth (dev mode) |

## Build

```bash
make build    # CGO_ENABLED=0, single static binary
make test     # go test -race
make vet      # go vet
```

## License

MIT
