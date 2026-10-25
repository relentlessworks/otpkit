package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/relentlessworks/otpkit/internal/model"
)

// Handler holds dependencies for HTTP handlers.
type Handler struct {
	NoAuth bool
}

// New creates a new Handler.
func New(noAuth bool) *Handler {
	return &Handler{NoAuth: noAuth}
}

// Routes returns the HTTP mux with all routes registered.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/help", h.help)
	mux.HandleFunc("/.well-known/agent.md", h.help)
	mux.HandleFunc("/totp", h.totp)
	mux.HandleFunc("/totp/verify", h.verifyTOTP)
	mux.HandleFunc("/totp/remaining", h.remaining)
	mux.HandleFunc("/totp/progress", h.progress)
	mux.HandleFunc("/hotp", h.hotp)
	mux.HandleFunc("/hotp/verify", h.verifyHOTP)
	mux.HandleFunc("/secret", h.generateSecret)
	mux.HandleFunc("/secret/hex", h.secretToHex)
	mux.HandleFunc("/hex/secret", h.hexToSecret)
	mux.HandleFunc("/uri", h.otpURI)
	mux.HandleFunc("/mcp", h.mcp)
	mux.HandleFunc("/", h.help)
	return mux
}

// wantsJSON checks if the client wants JSON output.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	return r.Header.Get("Accept") == "application/json"
}

// writeError writes an instructive error response.
func writeError(w http.ResponseWriter, r *http.Request, status int, msg, hint string) {
	w.WriteHeader(status)
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"error":"%s","hint":"%s"}`, msg, hint)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, "error: %s | hint: %s\n", msg, hint)
}

// writeText writes a plain text response.
func writeText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, text)
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, json string) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprint(w, json)
}

// writeRecord writes a record in the appropriate format.
func writeRecord(w http.ResponseWriter, r *http.Request, fields map[string]string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{"))
		first := true
		for k, v := range fields {
			if !first {
				w.Write([]byte(","))
			}
			first = false
			fmt.Fprintf(w, `"%s":"%s"`, k, v)
		}
		w.Write([]byte("}"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for k, v := range fields {
		fmt.Fprintf(w, "%s=%s ", k, v)
	}
	fmt.Fprintln(w)
}

// --- Handlers ---

func (h *Handler) totp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret= or in the request body")
		return
	}

	digits := getIntParam(r, "digits", model.DefaultDigits)
	period := getIntParam(r, "period", model.DefaultPeriod)
	algo := getAlgoParam(r, model.DefaultAlgo)
	at := getTimeParam(r, time.Now())

	code, err := model.TOTP(secret, digits, period, algo, at)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure secret is valid base32, digits 1-10, period > 0, algorithm is SHA1/SHA256/SHA512")
		return
	}

	remaining := model.RemainingSeconds(period, at)
	writeRecord(w, r, map[string]string{
		"code":      code,
		"digits":    fmt.Sprintf("%d", digits),
		"period":    fmt.Sprintf("%d", period),
		"algorithm": string(algo),
		"remaining": fmt.Sprintf("%d", remaining),
	})
}

func (h *Handler) verifyTOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret=")
		return
	}

	code := getParam(r, "code")
	if code == "" {
		writeError(w, r, http.StatusBadRequest, "missing code", "provide the OTP code to verify via ?code=")
		return
	}

	digits := getIntParam(r, "digits", model.DefaultDigits)
	period := getIntParam(r, "period", model.DefaultPeriod)
	algo := getAlgoParam(r, model.DefaultAlgo)
	window := getIntParam(r, "window", 1)
	at := getTimeParam(r, time.Now())

	ok, err := model.VerifyTOTP(secret, code, digits, period, algo, at, window)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure secret is valid base32 and parameters are correct")
		return
	}

	valid := "false"
	if ok {
		valid = "true"
	}
	writeRecord(w, r, map[string]string{
		"valid":  valid,
		"window": fmt.Sprintf("%d", window),
	})
}

func (h *Handler) remaining(w http.ResponseWriter, r *http.Request) {
	period := getIntParam(r, "period", model.DefaultPeriod)
	at := getTimeParam(r, time.Now())
	rem := model.RemainingSeconds(period, at)
	writeRecord(w, r, map[string]string{
		"remaining": fmt.Sprintf("%d", rem),
		"period":    fmt.Sprintf("%d", period),
	})
}

func (h *Handler) progress(w http.ResponseWriter, r *http.Request) {
	period := getIntParam(r, "period", model.DefaultPeriod)
	at := getTimeParam(r, time.Now())
	pct := model.ProgressPercent(period, at)
	rem := model.RemainingSeconds(period, at)
	writeRecord(w, r, map[string]string{
		"progress":  fmt.Sprintf("%d", pct),
		"remaining": fmt.Sprintf("%d", rem),
		"period":    fmt.Sprintf("%d", period),
	})
}

func (h *Handler) hotp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret=")
		return
	}

	counter := getUint64Param(r, "counter", model.DefaultCounter)
	digits := getIntParam(r, "digits", model.DefaultDigits)
	algo := getAlgoParam(r, model.DefaultAlgo)

	code, err := model.HOTP(secret, counter, digits, algo)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure secret is valid base32, digits 1-10, algorithm is SHA1/SHA256/SHA512")
		return
	}

	writeRecord(w, r, map[string]string{
		"code":    code,
		"counter": fmt.Sprintf("%d", counter),
		"digits":  fmt.Sprintf("%d", digits),
		"algo":    string(algo),
	})
}

func (h *Handler) verifyHOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret=")
		return
	}

	code := getParam(r, "code")
	if code == "" {
		writeError(w, r, http.StatusBadRequest, "missing code", "provide the OTP code to verify via ?code=")
		return
	}

	counter := getUint64Param(r, "counter", model.DefaultCounter)
	digits := getIntParam(r, "digits", model.DefaultDigits)
	algo := getAlgoParam(r, model.DefaultAlgo)
	window := getIntParam(r, "window", 0)

	ok, err := model.VerifyHOTP(secret, code, counter, digits, algo, window)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure secret is valid base32 and parameters are correct")
		return
	}

	valid := "false"
	if ok {
		valid = "true"
	}
	writeRecord(w, r, map[string]string{
		"valid":   valid,
		"counter": fmt.Sprintf("%d", counter),
		"window":  fmt.Sprintf("%d", window),
	})
}

func (h *Handler) generateSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	byteLen := getIntParam(r, "bytes", model.DefaultSecretLen)
	secret, err := model.GenerateSecret(byteLen)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to generate secret", "try again with default parameters")
		return
	}

	writeRecord(w, r, map[string]string{
		"secret": secret,
		"bytes":  fmt.Sprintf("%d", byteLen),
	})
}

func (h *Handler) secretToHex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret=")
		return
	}

	hex, err := model.SecretToHex(secret)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure secret is valid base32")
		return
	}

	writeRecord(w, r, map[string]string{
		"hex":    hex,
		"secret": secret,
	})
}

func (h *Handler) hexToSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	hexStr := getParam(r, "hex")
	if hexStr == "" {
		writeError(w, r, http.StatusBadRequest, "missing hex", "provide a hex-encoded string via ?hex=")
		return
	}

	secret, err := model.HexToSecret(hexStr)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, err.Error(), "ensure hex is a valid hex string")
		return
	}

	writeRecord(w, r, map[string]string{
		"secret": secret,
		"hex":    hexStr,
	})
}

func (h *Handler) otpURI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET or POST")
		return
	}

	secret := getParam(r, "secret")
	if secret == "" {
		writeError(w, r, http.StatusBadRequest, "missing secret", "provide a base32-encoded secret via ?secret=")
		return
	}

	label := getParam(r, "label")
	if label == "" {
		label = "user"
	}
	issuer := getParam(r, "issuer")
	digits := getIntParam(r, "digits", model.DefaultDigits)
	period := getIntParam(r, "period", model.DefaultPeriod)
	algo := getAlgoParam(r, model.DefaultAlgo)
	otpType := getParam(r, "type")
	if otpType == "" {
		otpType = "totp"
	}
	counter := getUint64Param(r, "counter", model.DefaultCounter)

	uri := model.OTPURI(label, issuer, secret, digits, period, algo, otpType, counter)
	writeRecord(w, r, map[string]string{
		"uri":   uri,
		"type":  otpType,
		"label": label,
	})
}

// --- Helpers ---

func getParam(r *http.Request, key string) string {
	// Check query params first
	v := r.URL.Query().Get(key)
	if v != "" {
		return v
	}
	// Check form body
	r.ParseForm()
	return r.FormValue(key)
}

func getIntParam(r *http.Request, key string, def int) int {
	v := getParam(r, key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func getUint64Param(r *http.Request, key string, def uint64) uint64 {
	v := getParam(r, key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func getAlgoParam(r *http.Request, def model.Algorithm) model.Algorithm {
	v := strings.ToUpper(getParam(r, "algorithm"))
	if v == "" {
		v = strings.ToUpper(getParam(r, "algo"))
	}
	switch v {
	case "SHA1":
		return model.AlgorithmSHA1
	case "SHA256":
		return model.AlgorithmSHA256
	case "SHA512":
		return model.AlgorithmSHA512
	default:
		return def
	}
}

func getTimeParam(r *http.Request, def time.Time) time.Time {
	v := getParam(r, "time")
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return time.Unix(n, 0)
}
