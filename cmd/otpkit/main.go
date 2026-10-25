package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/relentlessworks/otpkit/internal/api"
	"github.com/relentlessworks/otpkit/internal/config"
)

func main() {
	cfg := config.Load()

	handler := api.New(cfg.NoAuth)
	mux := handler.Routes()

	fmt.Fprintf(os.Stderr, "otpkit listening on %s\n", cfg.Addr)
	if cfg.NoAuth {
		fmt.Fprintf(os.Stderr, "WARNING: authentication disabled (dev mode)\n")
	}

	if err := http.ListenAndServe(cfg.Addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
