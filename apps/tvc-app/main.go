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
	Address         string           `json:"address"`
	Sanctioned      bool             `json:"sanctioned"`
	Identifications []Identification `json:"identifications"`
}

func main() {
	port := flag.Int("port", 8080, "port to listen on (bind 0.0.0.0)")
	apiKey := flag.String("chainalysis-api-key", os.Getenv("CHAINALYSIS_API_KEY"), "Chainalysis Sanctions API key")
	flag.Parse()

	if *apiKey == "" {
		log.Fatal("chainalysis-api-key is required (flag or CHAINALYSIS_API_KEY env var)")
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

		resp := screenResponse{
			Address:         req.Address,
			Sanctioned:      len(result.Identifications) > 0,
			Identifications: result.Identifications,
		}
		if resp.Identifications == nil {
			resp.Identifications = []Identification{}
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
