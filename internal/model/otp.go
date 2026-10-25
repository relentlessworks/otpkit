package model

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

// Algorithm represents the HMAC algorithm used for OTP generation.
type Algorithm string

const (
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// Default values per RFC 6238 and RFC 4226.
const (
	DefaultDigits   = 6
	DefaultPeriod   = 30
	DefaultCounter  = 0
	DefaultAlgo     = AlgorithmSHA1
	DefaultSecretLen = 20 // 160 bits, recommended by RFC 4226
)

// Secret represents a base32-encoded secret key.
type Secret string

// GenerateSecret generates a random secret key of the specified byte length
// and returns it as a base32-encoded string (no padding).
func GenerateSecret(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = DefaultSecretLen
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// decodeSecret decodes a base32-encoded secret into raw bytes.
// It handles both padded and unpadded base32, and uppercase/lowercase.
func decodeSecret(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)
	// Add padding if needed
	if len(s)%8 != 0 {
		s += strings.Repeat("=", 8-(len(s)%8))
	}
	dec, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid base32 secret: %w", err)
	}
	return dec, nil
}

// hashFunc returns the hash function for the given algorithm.
func hashFunc(algo Algorithm) (func() interface{}, error) {
	switch algo {
	case AlgorithmSHA1, "":
		return func() interface{} { return sha1.New() }, nil
	case AlgorithmSHA256:
		return func() interface{} { return sha256.New() }, nil
	case AlgorithmSHA512:
		return func() interface{} { return sha512.New() }, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

// computeHMAC computes the HMAC of the counter bytes using the given key and algorithm.
func computeHMAC(key []byte, counter uint64, algo Algorithm) ([]byte, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	switch algo {
	case AlgorithmSHA1, "":
		mac := hmac.New(sha1.New, key)
		mac.Write(buf[:])
		return mac.Sum(nil), nil
	case AlgorithmSHA256:
		mac := hmac.New(sha256.New, key)
		mac.Write(buf[:])
		return mac.Sum(nil), nil
	case AlgorithmSHA512:
		mac := hmac.New(sha512.New, key)
		mac.Write(buf[:])
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}

// dynamicTruncation implements the dynamic truncation from RFC 4226.
func dynamicTruncation(hmacResult []byte, digits int) string {
	offset := int(hmacResult[len(hmacResult)-1] & 0x0f)
	binaryCode := (int(hmacResult[offset])&0x7f)<<24 |
		(int(hmacResult[offset+1])&0xff)<<16 |
		(int(hmacResult[offset+2])&0xff)<<8 |
		(int(hmacResult[offset+3]) & 0xff)

	mod := int(math.Pow10(digits))
	otp := binaryCode % mod
	return fmt.Sprintf("%0*d", digits, otp)
}

// HOTP generates a counter-based OTP (RFC 4226).
func HOTP(secret string, counter uint64, digits int, algo Algorithm) (string, error) {
	if digits < 1 || digits > 10 {
		return "", fmt.Errorf("digits must be 1-10, got %d", digits)
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	hmacResult, err := computeHMAC(key, counter, algo)
	if err != nil {
		return "", err
	}
	return dynamicTruncation(hmacResult, digits), nil
}

// TOTP generates a time-based OTP (RFC 6238).
func TOTP(secret string, digits int, period int, algo Algorithm, at time.Time) (string, error) {
	if digits < 1 || digits > 10 {
		return "", fmt.Errorf("digits must be 1-10, got %d", digits)
	}
	if period <= 0 {
		return "", fmt.Errorf("period must be positive, got %d", period)
	}
	counter := uint64(at.Unix()) / uint64(period)
	return HOTP(secret, counter, digits, algo)
}

// VerifyTOTP checks if the given code matches the TOTP for the current time window
// (with optional look-ahead/look-behind for clock drift).
func VerifyTOTP(secret, code string, digits, period int, algo Algorithm, at time.Time, window int) (bool, error) {
	if window < 0 {
		window = 0
	}
	for i := -window; i <= window; i++ {
		t := at.Add(time.Duration(i*period) * time.Second)
		expected, err := TOTP(secret, digits, period, algo, t)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

// VerifyHOTP checks if the given code matches the HOTP for the given counter
// (with optional look-ahead window).
func VerifyHOTP(secret, code string, counter uint64, digits int, algo Algorithm, window int) (bool, error) {
	if window < 0 {
		window = 0
	}
	for i := uint64(0); i <= uint64(window); i++ {
		expected, err := HOTP(secret, counter+i, digits, algo)
		if err != nil {
			return false, err
		}
		if hmac.Equal([]byte(expected), []byte(code)) {
			return true, nil
		}
	}
	return false, nil
}

// OTPURI builds an otpauth:// URI for authenticator app setup (Google Authenticator, Authy, etc.).
func OTPURI(label, issuer, secret string, digits, period int, algo Algorithm, otpType string, counter uint64) string {
	if otpType == "" {
		otpType = "totp"
	}
	labelEscaped := url.PathEscape(label)
	if issuer != "" {
		labelEscaped = url.PathEscape(issuer + ":" + label)
	}

	params := url.Values{}
	params.Set("secret", strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", "")))
	if issuer != "" {
		params.Set("issuer", issuer)
	}
	params.Set("algorithm", string(algo))
	params.Set("digits", fmt.Sprintf("%d", digits))
	if otpType == "totp" {
		params.Set("period", fmt.Sprintf("%d", period))
	} else {
		params.Set("counter", fmt.Sprintf("%d", counter))
	}

	return fmt.Sprintf("otpauth://%s/%s?%s", otpType, labelEscaped, params.Encode())
}

// SecretToHex returns the hex representation of a base32 secret.
func SecretToHex(secret string) (string, error) {
	dec, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dec), nil
}

// HexToSecret converts a hex string to a base32-encoded secret.
func HexToSecret(hexStr string) (string, error) {
	dec, err := hex.DecodeString(hexStr)
	if err != nil {
		return "", fmt.Errorf("invalid hex: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(dec), nil
}

// RemainingSeconds returns the number of seconds until the next TOTP window.
func RemainingSeconds(period int, at time.Time) int {
	if period <= 0 {
		period = DefaultPeriod
	}
	return period - int(at.Unix()%int64(period))
}

// ProgressPercent returns the progress (0-100) of the current TOTP window.
func ProgressPercent(period int, at time.Time) int {
	if period <= 0 {
		period = DefaultPeriod
	}
	elapsed := int(at.Unix() % int64(period))
	return int(float64(elapsed) / float64(period) * 100)
}
