package config

import (
	"flag"
	"os"
)

// Config holds all configuration for the OTP service.
type Config struct {
	Addr   string
	NoAuth bool
}

// Default returns a Config with sensible defaults.
func Default() *Config {
	return &Config{
		Addr:   ":8470",
		NoAuth: false,
	}
}

// Load parses flags and environment variables, returning a Config.
// Precedence: defaults < env < flags.
func Load() *Config {
	c := Default()

	// Env
	if v := os.Getenv("OTPKIT_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("OTPKIT_NO_AUTH"); v == "true" || v == "1" {
		c.NoAuth = true
	}

	// Flags
	flag.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	flag.BoolVar(&c.NoAuth, "no-auth", c.NoAuth, "disable authentication (dev mode)")
	flag.Parse()

	return c
}
