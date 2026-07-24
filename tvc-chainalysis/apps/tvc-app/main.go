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
type screenResponse struct {
	Address          string           `json:"address"`
	Sanctioned       bool             `json:"sanctioned"`
	Identifications  []Identification `json:"identifications"`
	AppProof         *AppProof        `json:"appProof"`
	BootEphemeralKey string           `json:"bootEphemeralKey,omitempty"`
}

// server holds the dependencies shared by the HTTP handlers.
type server struct {
	chainalysis      *ChainalysisClient
	signingKey       *ecdsa.PrivateKey
	bootEphemeralKey string
}

func main() {
	port := flag.Int("port", 8080, "port to listen on (bind 0.0.0.0)")
	apiKey := flag.String("chainalysis-api-key", os.Getenv("CHAINALYSIS_API_KEY"), "Chainalysis Sanctions API key")
	flag.Parse()

	if *apiKey == "" {
		log.Fatal("chainalysis-api-key is required (flag or CHAINALYSIS_API_KEY env var)")
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
		chainalysis:      NewChainalysisClient(*apiKey),
		signingKey:       signingKey,
		bootEphemeralKey: bootEphemeralKey,
	}

	mux := http.NewServeMux()

	// Health check — required by TVC (GET /health → 200).
	mux.HandleFunc("GET /health", healthcheck)

	// Screen an address for sanctions.
	mux.HandleFunc("POST /screen", srv.handleScreen)

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("tvc-chainalysis listening on %s", addr)
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

// handleScreen screens an address for sanctions and returns the result signed
// with the enclave's ephemeral key (when available) plus the boot ephemeral key.
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

	result, err := s.chainalysis.CheckAddress(r.Context(), req.Address)
	if err != nil {
		log.Printf("chainalysis error for %s: %v", req.Address, err)
		http.Error(w, `{"error":"sanctions check failed"}`, http.StatusInternalServerError)
		return
	}

	sanctioned := len(result.Identifications) > 0
	identifications := result.Identifications

	appProof, err := signScreening(s.signingKey, req.Address, sanctioned, identifications)
	if err != nil {
		log.Printf("WARNING: could not sign screening result: %v", err)
	}

	resp := screenResponse{
		Address:          req.Address,
		Sanctioned:       sanctioned,
		Identifications:  identifications,
		AppProof:         appProof,
		BootEphemeralKey: s.bootEphemeralKey,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
