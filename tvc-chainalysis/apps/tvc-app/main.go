package main

import (
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

	chainalysis := NewChainalysisClient(*apiKey)
	mux := http.NewServeMux()

	// Health check — required by TVC (GET /health → 200).
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, `{"status":"ok"}`)
	})

	// Screen an address for sanctions.
	mux.HandleFunc("POST /screen", func(w http.ResponseWriter, r *http.Request) {
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

		result, err := chainalysis.CheckAddress(r.Context(), req.Address)
		if err != nil {
			log.Printf("chainalysis error for %s: %v", req.Address, err)
			http.Error(w, `{"error":"sanctions check failed"}`, http.StatusInternalServerError)
			return
		}

		sanctioned := len(result.Identifications) > 0
		identifications := result.Identifications
		if identifications == nil {
			identifications = []Identification{}
		}

		appProof, err := signScreening(signingKey, req.Address, sanctioned, identifications)
		if err != nil {
			log.Printf("WARNING: could not sign screening result: %v", err)
		}

		resp := screenResponse{
			Address:          req.Address,
			Sanctioned:       sanctioned,
			Identifications:  identifications,
			AppProof:         appProof,
			BootEphemeralKey: bootEphemeralKey,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", *port)
	log.Printf("tvc-chainalysis listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
