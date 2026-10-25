package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/relentlessworks/otpkit/internal/model"
)

// MCPRequest is a JSON-RPC 2.0 request.
type MCPRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// MCPResponse is a JSON-RPC 2.0 response.
type MCPResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError is a JSON-RPC 2.0 error.
type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPTool represents a tool in the MCP tools/list response.
type MCPTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// MCPToolCallParams holds the tool name and arguments.
type MCPToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

func (h *Handler) mcp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST for MCP")
		return
	}

	var req MCPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeMCPError(w, nil, -32700, "parse error")
		return
	}

	switch req.Method {
	case "initialize":
		writeMCPResult(w, req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "otpkit",
				"version": "0.1.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		})

	case "tools/list":
		tools := []MCPTool{
			{"generate_totp", "Generate a time-based OTP code (RFC 6238). Args: secret (base32), digits (default 6), period (default 30), algorithm (SHA1/SHA256/SHA512), time (Unix timestamp, optional)."},
			{"verify_totp", "Verify a TOTP code. Args: secret, code, digits, period, algorithm, window (look-ahead/behind, default 1), time (optional)."},
			{"generate_hotp", "Generate a counter-based OTP code (RFC 4226). Args: secret, counter, digits, algorithm."},
			{"verify_hotp", "Verify an HOTP code. Args: secret, code, counter, digits, algorithm, window."},
			{"generate_secret", "Generate a random base32 secret. Args: bytes (default 20)."},
			{"secret_to_hex", "Convert base32 secret to hex. Args: secret."},
			{"hex_to_secret", "Convert hex to base32 secret. Args: hex."},
			{"otp_uri", "Generate otpauth:// URI. Args: secret, label, issuer, type (totp/hotp), digits, period, algorithm, counter."},
			{"remaining", "Seconds remaining in current TOTP window. Args: period."},
			{"progress", "Progress of current TOTP window. Args: period."},
		}
		writeMCPResult(w, req.ID, map[string]interface{}{"tools": tools})

	case "tools/call":
		var params MCPToolCallParams
		if err := json.Unmarshal(req.Params, &params); err != nil {
			writeMCPError(w, req.ID, -32602, "invalid params")
			return
		}
		result, err := h.handleMCPTool(params)
		if err != nil {
			writeMCPError(w, req.ID, -32603, err.Error())
			return
		}
		writeMCPResult(w, req.ID, map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": result},
			},
		})

	default:
		writeMCPError(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

func (h *Handler) handleMCPTool(params MCPToolCallParams) (string, error) {
	get := func(key string, def string) string {
		if v, ok := params.Arguments[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return def
	}
	getInt := func(key string, def int) int {
		if v, ok := params.Arguments[key]; ok {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			default:
				return def
			}
		}
		return def
	}
	getUint64 := func(key string, def uint64) uint64 {
		if v, ok := params.Arguments[key]; ok {
			switch n := v.(type) {
			case float64:
				return uint64(n)
			case int:
				return uint64(n)
			default:
				return def
			}
		}
		return def
	}

	switch params.Name {
	case "generate_totp":
		secret := get("secret", "")
		if secret == "" {
			return "", fmt.Errorf("missing secret")
		}
		digits := getInt("digits", model.DefaultDigits)
		period := getInt("period", model.DefaultPeriod)
		algo := model.Algorithm(get("algorithm", string(model.DefaultAlgo)))
		code, err := model.TOTP(secret, digits, period, algo, time.Now())
		if err != nil {
			return "", err
		}
		rem := model.RemainingSeconds(period, time.Now())
		return fmt.Sprintf("code=%s digits=%d period=%d algorithm=%s remaining=%d", code, digits, period, algo, rem), nil

	case "verify_totp":
		secret := get("secret", "")
		code := get("code", "")
		if secret == "" || code == "" {
			return "", fmt.Errorf("missing secret or code")
		}
		digits := getInt("digits", model.DefaultDigits)
		period := getInt("period", model.DefaultPeriod)
		algo := model.Algorithm(get("algorithm", string(model.DefaultAlgo)))
		window := getInt("window", 1)
		ok, err := model.VerifyTOTP(secret, code, digits, period, algo, time.Now(), window)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("valid=%v window=%d", ok, window), nil

	case "generate_hotp":
		secret := get("secret", "")
		if secret == "" {
			return "", fmt.Errorf("missing secret")
		}
		counter := getUint64("counter", model.DefaultCounter)
		digits := getInt("digits", model.DefaultDigits)
		algo := model.Algorithm(get("algorithm", string(model.DefaultAlgo)))
		code, err := model.HOTP(secret, counter, digits, algo)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("code=%s counter=%d digits=%d algorithm=%s", code, counter, digits, algo), nil

	case "verify_hotp":
		secret := get("secret", "")
		code := get("code", "")
		if secret == "" || code == "" {
			return "", fmt.Errorf("missing secret or code")
		}
		counter := getUint64("counter", model.DefaultCounter)
		digits := getInt("digits", model.DefaultDigits)
		algo := model.Algorithm(get("algorithm", string(model.DefaultAlgo)))
		window := getInt("window", 0)
		ok, err := model.VerifyHOTP(secret, code, counter, digits, algo, window)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("valid=%v counter=%d window=%d", ok, counter, window), nil

	case "generate_secret":
		byteLen := getInt("bytes", model.DefaultSecretLen)
		secret, err := model.GenerateSecret(byteLen)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("secret=%s bytes=%d", secret, byteLen), nil

	case "secret_to_hex":
		secret := get("secret", "")
		if secret == "" {
			return "", fmt.Errorf("missing secret")
		}
		hex, err := model.SecretToHex(secret)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("hex=%s secret=%s", hex, secret), nil

	case "hex_to_secret":
		hexStr := get("hex", "")
		if hexStr == "" {
			return "", fmt.Errorf("missing hex")
		}
		secret, err := model.HexToSecret(hexStr)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("secret=%s hex=%s", secret, hexStr), nil

	case "otp_uri":
		secret := get("secret", "")
		if secret == "" {
			return "", fmt.Errorf("missing secret")
		}
		label := get("label", "user")
		issuer := get("issuer", "")
		otpType := get("type", "totp")
		digits := getInt("digits", model.DefaultDigits)
		period := getInt("period", model.DefaultPeriod)
		algo := model.Algorithm(get("algorithm", string(model.DefaultAlgo)))
		counter := getUint64("counter", model.DefaultCounter)
		uri := model.OTPURI(label, issuer, secret, digits, period, algo, otpType, counter)
		return fmt.Sprintf("uri=%s type=%s label=%s", uri, otpType, label), nil

	case "remaining":
		period := getInt("period", model.DefaultPeriod)
		rem := model.RemainingSeconds(period, time.Now())
		return fmt.Sprintf("remaining=%d period=%d", rem, period), nil

	case "progress":
		period := getInt("period", model.DefaultPeriod)
		pct := model.ProgressPercent(period, time.Now())
		rem := model.RemainingSeconds(period, time.Now())
		return fmt.Sprintf("progress=%d remaining=%d period=%d", pct, rem, period), nil

	default:
		return "", fmt.Errorf("unknown tool: %s", params.Name)
	}
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func writeMCPError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	resp := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    code,
			Message: msg,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
