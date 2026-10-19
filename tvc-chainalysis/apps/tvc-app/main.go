package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

// screenRequest is the JSON body expected by POST /screen.
type screenRequest struct {
	Address string `json:"address"`
}

// screenResponse is returned by POST /screen.
//
// Field naming mirrors the enriched Hermod result. The `isThreat` boolean is
// the top-line signal; the enrichment fields (threatLevel, hitUuid,
// hashedInvestigation, sanctioned) are only populated on a hit and callers
// must not treat their zero values as meaningful on a miss.
//
// NOTE: The response deliberately does NOT include the raw HMAC key or
// anything that would let a receiver rebuild the address→signature mapping
// for a different key. `hashedAddress` is the signature Hermod echoed back;
// that is safe to include because Hermod computed it from an input the
// enclave already had.
type screenResponse struct {
	Address             string    `json:"address"`
	IsThreat            bool      `json:"isThreat"`
	ThreatLevel         int       `json:"threatLevel,omitempty"`
	HitUUID             string    `json:"hitUuid,omitempty"`
	HashedAddress       string    `json:"hashedAddress,omitempty"`
	HashedInvestigation string    `json:"hashedInvestigation,omitempty"`
	Sanctioned          string    `json:"sanctioned,omitempty"`
	AppProof            *AppProof `json:"appProof"`
	BootEphemeralKey    string    `json:"bootEphemeralKey,omitempty"`
}

// server holds the dependencies shared by the HTTP handlers.
type server struct {
	hermod           *HermodClient
	signingKey       *ecdsa.PrivateKey
	bootEphemeralKey string
}

func main() {
	port := flag.Int("port", 8080, "port to listen on (bind 0.0.0.0)")

	// Hermod configuration. All three are read from flags with env-var
	// fallbacks. NEVER log HERMOD_HMAC_KEY or HERMOD_API_KEY, and never log
	// the raw address alongside the HMAC key (would leak the pairing).
	hermodURL := flag.String("hermod-url", os.Getenv("HERMOD_URL"), "base URL of the Hermod threat-intel agent (e.g. http://hermod:8080)")
	hermodHMACKey := flag.String("hermod-hmac-key", os.Getenv("HERMOD_HMAC_KEY"), "per-account HMAC-SHA256 key for signing addresses to Hermod")
	hermodAPIKey := flag.String("hermod-api-key", os.Getenv("HERMOD_API_KEY"), "optional bearer token for the Hermod agent")
	flag.Parse()

	if *hermodURL == "" {
		log.Fatal("hermod-url is required (flag or HERMOD_URL env var)")
	}
	if *hermodHMACKey == "" {
		log.Fatal("hermod-hmac-key is required (flag or HERMOD_HMAC_KEY env var)")
	}

	signingKey, masterSeed, err := loadEphemeralSigningKey()
	if err != nil {
		log.Printf("WARNING: could not load ephemeral signing key: %v — app proofs will be omitted", err)
	} else if signingKey == nil {
		log.Printf("WARNING: ephemeral key file not found — app proofs will be omitted (expected outside enclave)")
	} else {
		log.Printf("ephemeral signing key loaded")
	}

	var bootEphemeralKey string
	if masterSeed != nil {
		bootEphemeralKey, err = buildBootEphemeralKey(masterSeed)
		if err != nil {
			log.Printf("WARNING: could not build boot ephemeral key: %v", err)
		} else {
			log.Printf("boot ephemeral key built (%d chars)", len(bootEphemeralKey))
		}
	}

	srv := &server{
		hermod:           NewHermodClient(*hermodURL, *hermodHMACKey, *hermodAPIKey),
		signingKey:       signingKey,
		bootEphemeralKey: bootEphemeralKey,
	}

	// Log the Hermod base URL (safe — no credentials) but never the HMAC key
	// or bearer token. Even the length is enough to leak information about
	// the account's key rotation state; do not log it.
	log.Printf("hermod client configured (baseURL=%s, bearerConfigured=%t)", *hermodURL, *hermodAPIKey != "")

	mux := http.NewServeMux()

	// Health check — required by TVC (GET /health → 200).
	mux.HandleFunc("GET /health", healthcheck)

	// Screen an address for threats via Hermod.
	mux.HandleFunc("POST /screen", srv.handleScreen)

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("tvc-threat-screener listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// healthcheck responds 200 with a small JSON body. TVC requires GET /health.
func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, `{"status":"ok"}`)
}

// handleScreen screens an address via Hermod and returns the result signed
// with the enclave's ephemeral key (when available) plus the boot ephemeral key.
//
// IMPORTANT — "never cache a miss" semantic:
// A Hermod 404 (IsThreat=false) means "not a known threat right now" only.
// It is NOT evidence of future safety. Every transaction that touches an
// address must re-run the screen; downstream consumers must not treat
// past misses as permanent clearances. The web UI surfaces this to users
// via a note near the miss result.
func (s *server) handleScreen(w http.ResponseWriter, r *http.Request) {
	var req screenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	req.Address = strings.TrimSpace(req.Address)
	if req.Address == "" {
		http.Error(w, `{"error":"address is required"}`, http.StatusBadRequest)
		return
	}

	result, err := s.hermod.CheckAddress(r.Context(), req.Address)
	if err != nil {
		// Log the address (already sanitized) and the error message — but
		// NEVER the HMAC key or the raw request headers, which could carry
		// the bearer token forwarded from a misconfigured caller.
		log.Printf("hermod error for %s: %v", req.Address, err)
		http.Error(w, `{"error":"threat check failed"}`, http.StatusInternalServerError)
		return
	}

	appProof, err := signHermodScreening(s.signingKey, result)
	if err != nil {
		log.Printf("WARNING: could not sign screening result: %v", err)
	}

	resp := screenResponse{
		Address:             result.Address,
		IsThreat:            result.IsThreat,
		ThreatLevel:         result.ThreatLevel,
		HitUUID:             result.HitUUID,
		HashedAddress:       result.HashedAddress,
		HashedInvestigation: result.HashedInvestigation,
		Sanctioned:          result.Sanctioned,
		AppProof:            appProof,
		BootEphemeralKey:    s.bootEphemeralKey,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
