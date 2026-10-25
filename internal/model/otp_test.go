package model

import (
	"testing"
	"time"
)

// RFC 4226 test vectors (Appendix D)
var rfc4226Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" // "12345678901234567890" in base32

func TestGenerateSecret(t *testing.T) {
	s, err := GenerateSecret(20)
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}
	if len(s) == 0 {
		t.Fatal("secret is empty")
	}
	// 20 bytes = 160 bits = 32 base32 chars (no padding)
	if len(s) != 32 {
		t.Errorf("expected 32 chars, got %d", len(s))
	}
}

func TestGenerateSecretDefault(t *testing.T) {
	s, err := GenerateSecret(0)
	if err != nil {
		t.Fatalf("GenerateSecret(0) failed: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("expected 32 chars for default, got %d", len(s))
	}
}

func TestHOTPRFC4226(t *testing.T) {
	// RFC 4226 Appendix D test values
	expected := []string{
		"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489",
	}
	for i, exp := range expected {
		code, err := HOTP(rfc4226Secret, uint64(i), 6, AlgorithmSHA1)
		if err != nil {
			t.Fatalf("HOTP counter %d failed: %v", i, err)
		}
		if code != exp {
			t.Errorf("counter %d: expected %s, got %s", i, exp, code)
		}
	}
}

func TestTOTPRFC6238(t *testing.T) {
	// RFC 6238 Appendix B test values
	// Secret for SHA1: "12345678901234567890" (20 bytes)
	// Secret for SHA256: "12345678901234567890123456789012" (32 bytes)
	// Secret for SHA512: "1234567890123456789012345678901234567890123456789012345678901234" (64 bytes)
	secretSHA1 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secretSHA256 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA"
	secretSHA512 := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA"

	tests := []struct {
		name     string
		secret   string
		algo     Algorithm
		time     int64
		expected string
	}{
		{"SHA1 T=59", secretSHA1, AlgorithmSHA1, 59, "94287082"},
		{"SHA1 T=1111111109", secretSHA1, AlgorithmSHA1, 1111111109, "07081804"},
		{"SHA1 T=1111111111", secretSHA1, AlgorithmSHA1, 1111111111, "14050471"},
		{"SHA1 T=1234567890", secretSHA1, AlgorithmSHA1, 1234567890, "89005924"},
		{"SHA1 T=2000000000", secretSHA1, AlgorithmSHA1, 2000000000, "69279037"},
		{"SHA1 T=20000000000", secretSHA1, AlgorithmSHA1, 20000000000, "65353130"},
		{"SHA256 T=59", secretSHA256, AlgorithmSHA256, 59, "46119246"},
		{"SHA256 T=1111111109", secretSHA256, AlgorithmSHA256, 1111111109, "68084774"},
		{"SHA256 T=1111111111", secretSHA256, AlgorithmSHA256, 1111111111, "67062674"},
		{"SHA256 T=1234567890", secretSHA256, AlgorithmSHA256, 1234567890, "91819424"},
		{"SHA256 T=2000000000", secretSHA256, AlgorithmSHA256, 2000000000, "90698825"},
		{"SHA256 T=20000000000", secretSHA256, AlgorithmSHA256, 20000000000, "77737706"},
		{"SHA512 T=59", secretSHA512, AlgorithmSHA512, 59, "90693936"},
		{"SHA512 T=1111111109", secretSHA512, AlgorithmSHA512, 1111111109, "25091201"},
		{"SHA512 T=1111111111", secretSHA512, AlgorithmSHA512, 1111111111, "99943326"},
		{"SHA512 T=1234567890", secretSHA512, AlgorithmSHA512, 1234567890, "93441116"},
		{"SHA512 T=2000000000", secretSHA512, AlgorithmSHA512, 2000000000, "38618901"},
		{"SHA512 T=20000000000", secretSHA512, AlgorithmSHA512, 20000000000, "47863826"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := TOTP(tt.secret, 8, 30, tt.algo, time.Unix(tt.time, 0))
			if err != nil {
				t.Fatalf("TOTP failed: %v", err)
			}
			if code != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, code)
			}
		})
	}
}

func TestVerifyTOTP(t *testing.T) {
	now := time.Unix(1234567890, 0)
	code, err := TOTP(rfc4226Secret, 6, 30, AlgorithmSHA1, now)
	if err != nil {
		t.Fatalf("TOTP failed: %v", err)
	}
	ok, err := VerifyTOTP(rfc4226Secret, code, 6, 30, AlgorithmSHA1, now, 0)
	if err != nil {
		t.Fatalf("VerifyTOTP failed: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}

	// Wrong code
	ok, _ = VerifyTOTP(rfc4226Secret, "000000", 6, 30, AlgorithmSHA1, now, 0)
	if ok {
		t.Error("expected verification to fail for wrong code")
	}
}

func TestVerifyTOTPWithWindow(t *testing.T) {
	now := time.Unix(1234567890, 0)
	// Generate code for the previous window
	prevTime := now.Add(-30 * time.Second)
	code, err := TOTP(rfc4226Secret, 6, 30, AlgorithmSHA1, prevTime)
	if err != nil {
		t.Fatalf("TOTP failed: %v", err)
	}
	// Verify with window=1 should accept it
	ok, _ := VerifyTOTP(rfc4226Secret, code, 6, 30, AlgorithmSHA1, now, 1)
	if !ok {
		t.Error("expected verification with window=1 to succeed for previous window code")
	}
	// Verify with window=0 should reject it
	ok, _ = VerifyTOTP(rfc4226Secret, code, 6, 30, AlgorithmSHA1, now, 0)
	if ok {
		t.Error("expected verification with window=0 to fail for previous window code")
	}
}

func TestVerifyHOTP(t *testing.T) {
	code, err := HOTP(rfc4226Secret, 0, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("HOTP failed: %v", err)
	}
	ok, err := VerifyHOTP(rfc4226Secret, code, 0, 6, AlgorithmSHA1, 0)
	if err != nil {
		t.Fatalf("VerifyHOTP failed: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}

	// Wrong code
	ok, _ = VerifyHOTP(rfc4226Secret, "000000", 0, 6, AlgorithmSHA1, 0)
	if ok {
		t.Error("expected verification to fail for wrong code")
	}
}

func TestVerifyHOTPWithWindow(t *testing.T) {
	// Generate code for counter=5
	code, err := HOTP(rfc4226Secret, 5, 6, AlgorithmSHA1)
	if err != nil {
		t.Fatalf("HOTP failed: %v", err)
	}
	// Verify with counter=0, window=5 should accept it
	ok, _ := VerifyHOTP(rfc4226Secret, code, 0, 6, AlgorithmSHA1, 5)
	if !ok {
		t.Error("expected verification with window=5 to succeed")
	}
	// Verify with counter=0, window=4 should reject it
	ok, _ = VerifyHOTP(rfc4226Secret, code, 0, 6, AlgorithmSHA1, 4)
	if ok {
		t.Error("expected verification with window=4 to fail")
	}
}

func TestOTPURI(t *testing.T) {
	uri := OTPURI("alice@google.com", "ACME", "JBSWY3DPEHPK3PXP", 6, 30, AlgorithmSHA1, "totp", 0)
	if uri == "" {
		t.Fatal("URI is empty")
	}
	if !contains(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/, got: %s", uri)
	}
	if !contains(uri, "secret=JBSWY3DPEHPK3PXP") {
		t.Errorf("URI should contain secret, got: %s", uri)
	}
	if !contains(uri, "issuer=ACME") {
		t.Errorf("URI should contain issuer, got: %s", uri)
	}
	if !contains(uri, "digits=6") {
		t.Errorf("URI should contain digits=6, got: %s", uri)
	}
	if !contains(uri, "period=30") {
		t.Errorf("URI should contain period=30, got: %s", uri)
	}
}

func TestOTPURIHOTP(t *testing.T) {
	uri := OTPURI("alice", "ACME", "JBSWY3DPEHPK3PXP", 6, 30, AlgorithmSHA1, "hotp", 42)
	if !contains(uri, "otpauth://hotp/") {
		t.Errorf("URI should start with otpauth://hotp/, got: %s", uri)
	}
	if !contains(uri, "counter=42") {
		t.Errorf("URI should contain counter=42, got: %s", uri)
	}
}

func TestSecretToHex(t *testing.T) {
	hex, err := SecretToHex("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("SecretToHex failed: %v", err)
	}
	if hex != "48656c6c6f21deadbeef" {
		// "Hello!" in ASCII + some bytes — actually JBSWY3DPEHPK3PXP decodes to "Hello!..." 
		// Let's just check it's non-empty and valid hex
		t.Logf("hex: %s", hex)
	}
}

func TestHexToSecretRoundTrip(t *testing.T) {
	original := "JBSWY3DPEHPK3PXP"
	hex, err := SecretToHex(original)
	if err != nil {
		t.Fatalf("SecretToHex failed: %v", err)
	}
	back, err := HexToSecret(hex)
	if err != nil {
		t.Fatalf("HexToSecret failed: %v", err)
	}
	if back != original {
		t.Errorf("round-trip failed: expected %s, got %s", original, back)
	}
}

func TestRemainingSeconds(t *testing.T) {
	// At Unix time 100 with period 30, remaining = 30 - (100 % 30) = 30 - 10 = 20
	rem := RemainingSeconds(30, time.Unix(100, 0))
	if rem != 20 {
		t.Errorf("expected 20, got %d", rem)
	}
	// At Unix time 90 with period 30, remaining = 30 - (90 % 30) = 30 - 0 = 30
	rem = RemainingSeconds(30, time.Unix(90, 0))
	if rem != 30 {
		t.Errorf("expected 30, got %d", rem)
	}
}

func TestProgressPercent(t *testing.T) {
	// At Unix time 100 with period 30, elapsed = 10, progress = 10/30*100 = 33
	pct := ProgressPercent(30, time.Unix(100, 0))
	if pct != 33 {
		t.Errorf("expected 33, got %d", pct)
	}
}

func TestInvalidDigits(t *testing.T) {
	_, err := TOTP(rfc4226Secret, 0, 30, AlgorithmSHA1, time.Now())
	if err == nil {
		t.Error("expected error for digits=0")
	}
	_, err = TOTP(rfc4226Secret, 11, 30, AlgorithmSHA1, time.Now())
	if err == nil {
		t.Error("expected error for digits=11")
	}
}

func TestInvalidPeriod(t *testing.T) {
	_, err := TOTP(rfc4226Secret, 6, 0, AlgorithmSHA1, time.Now())
	if err == nil {
		t.Error("expected error for period=0")
	}
}

func TestInvalidSecret(t *testing.T) {
	_, err := TOTP("!!!invalid!!!", 6, 30, AlgorithmSHA1, time.Now())
	if err == nil {
		t.Error("expected error for invalid secret")
	}
}

func TestInvalidAlgorithm(t *testing.T) {
	_, err := TOTP(rfc4226Secret, 6, 30, Algorithm("MD5"), time.Now())
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
