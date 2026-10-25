package api

import (
	"fmt"
	"net/http"
)

func (h *Handler) help(w http.ResponseWriter, r *http.Request) {
	text := `otpkit — Agentic-first TOTP and HOTP generation and verification service

RFC 6238 (TOTP) and RFC 4226 (HOTP) compliant. Stateless computation, no database.

== ENDPOINTS ==

GET /totp?secret=BASE32&digits=6&period=30&algorithm=SHA1&time=UNIX
  Generate a time-based OTP code.
  - secret: base32-encoded secret key (required)
  - digits: 1-10 (default 6)
  - period: seconds per window (default 30)
  - algorithm: SHA1, SHA256, SHA512 (default SHA1)
  - time: Unix timestamp (default: now)

GET /totp/verify?secret=BASE32&code=123456&digits=6&period=30&window=1
  Verify a TOTP code. window = look-ahead/behind windows for clock drift.

GET /totp/remaining?period=30
  Seconds remaining in the current TOTP window.

GET /totp/progress?period=30
  Progress percentage and remaining seconds in current window.

GET /hotp?secret=BASE32&counter=0&digits=6&algorithm=SHA1
  Generate a counter-based OTP code.

GET /hotp/verify?secret=BASE32&code=123456&counter=0&window=0
  Verify an HOTP code. window = look-ahead counters.

GET /secret?bytes=20
  Generate a random base32 secret key (default 20 bytes / 160 bits).

GET /secret/hex?secret=BASE32
  Convert a base32 secret to hex.

GET /hex/secret?hex=HEXSTRING
  Convert hex to a base32 secret.

GET /uri?secret=BASE32&label=user&issuer=ACME&type=totp&digits=6&period=30&algorithm=SHA1
  Generate an otpauth:// URI for authenticator app setup.
  - type: totp or hotp (default totp)
  - counter: required for hotp type

POST /mcp
  MCP JSON-RPC 2.0 endpoint. Tools: generate_totp, verify_totp, generate_hotp,
  verify_hotp, generate_secret, secret_to_hex, hex_to_secret, otp_uri,
  remaining, progress.

== OUTPUT FORMAT ==

Plain text by default: space-separated key=value pairs, one record per line.
JSON: send Accept: application/json or add ?format=json

== ERRORS ==

error: message | hint: what to do next

== EXAMPLES ==

  curl "http://localhost:8470/totp?secret=JBSWY3DPEHPK3PXP"
  # code=123456 digits=6 period=30 algorithm=SHA1 remaining=25

  curl "http://localhost:8470/totp/verify?secret=JBSWY3DPEHPK3PXP&code=123456"
  # valid=true window=1

  curl "http://localhost:8470/secret"
  # secret=KRSXG5BAIFAUKVTFNFGGYZLTNE bytes=20

  curl "http://localhost:8470/uri?secret=JBSWY3DPEHPK3PXP&label=alice&issuer=ACME"
  # uri=otpauth://totp/ACME:alice?secret=JBSWY3DPEHPK3PXP&issuer=ACME&algorithm=SHA1&digits=6&period=30 type=totp label=alice
`
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, text)
}
