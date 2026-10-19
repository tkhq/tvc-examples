package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HermodResult is the enriched, TVC-app-internal representation of a
// screening result returned by zeroShadow's Hermod threat-intel agent.
//
// A "hit" (HTTP 200 from the /addresses/<sig> endpoint) means the address
// matched an entry Hermod knows about. A "miss" (HTTP 404) means the address
// is not known to Hermod right now — it is EXPLICITLY NOT a proof of future
// safety. See the "never cache a miss" comment in main.go and the note in
// the web UI: misses are point-in-time and must be re-checked per-transaction.
type HermodResult struct {
	// Address is the raw address the caller asked us to screen (trimmed).
	// It is NOT the HMAC signature.
	Address string `json:"address"`

	// IsThreat is true when Hermod returned HTTP 200 (address is known/tracked).
	// False when Hermod returned HTTP 404. Other statuses are surfaced as errors.
	IsThreat bool `json:"isThreat"`

	// The fields below are only populated on a hit (IsThreat=true). On a miss
	// they are zero values; consumers must not read them as meaningful defaults.

	// ID is Hermod's numeric identifier for the hit record.
	ID int64 `json:"id,omitempty"`

	// ThreatLevel is a 1..10 severity, 10=most severe.
	ThreatLevel int `json:"threatLevel,omitempty"`

	// HitUUID is a stable per-hit UUID assigned by Hermod.
	HitUUID string `json:"hitUuid,omitempty"`

	// HashedAddress echoes back the HMAC-SHA256 signature we sent in the URL.
	// Useful as a self-check that the response matches the request without
	// re-exposing the plaintext address downstream.
	HashedAddress string `json:"hashedAddress,omitempty"`

	// HashedInvestigation groups addresses that share the same case at Hermod.
	// Addresses in the same investigation share this value.
	HashedInvestigation string `json:"hashedInvestigation,omitempty"`

	// Sanctioned is the sanctions program the address falls under
	// (e.g. "OFAC"). Empty string when Hermod did not report one.
	Sanctioned string `json:"sanctioned,omitempty"`
}

// HermodClient is a thin wrapper around zeroShadow's Hermod agent API.
//
// The client is expected to point at a Hermod instance the operator runs —
// either co-located with the TVC app as a sidecar, or reachable over the
// network (which requires TVC externalConnectivity to be enabled).
type HermodClient struct {
	baseURL    string
	hmacKey    []byte
	apiKey     string // optional bearer token; empty means no Authorization header
	httpClient *http.Client
}

// NewHermodClient constructs a Hermod client.
//
// baseURL is the root URL of the Hermod agent (e.g. "http://hermod:8080").
// hmacKey is the per-account HMAC secret used to sign addresses. It MUST NOT
// be logged, and MUST NEVER be joined with the raw address anywhere that
// gets logged.
// apiKey is optional; when non-empty it is sent as a bearer token.
func NewHermodClient(baseURL, hmacKey, apiKey string) *HermodClient {
	return &HermodClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		hmacKey: []byte(hmacKey),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// signAddress computes HMAC-SHA256(address, hmacKey) and returns the
// lowercase hex encoding — the value Hermod expects in the URL path.
//
// The address is used verbatim (trim whitespace before calling). Callers
// decide whether to sign the lowercase or checksummed form for EVM
// addresses; both are valid per Hermod's spec. Non-EVM addresses must be
// passed exactly as they appear on-chain.
func signAddress(address string, hmacKey []byte) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(address))
	return hex.EncodeToString(mac.Sum(nil))
}

// SignAddress is the exported wrapper for signAddress that uses the
// client's configured HMAC key. Exposed so main.go can log the signature
// (which is safe — it's already opaque) without ever seeing the raw key.
func (c *HermodClient) SignAddress(address string) string {
	return signAddress(address, c.hmacKey)
}

// CheckAddress queries Hermod for the given address.
//
// The address is trimmed before signing. Callers should pass the canonical
// form for the chain (lowercase or checksummed for EVM, native encoding
// for other chains).
//
// HTTP status is the primary signal:
//   - 200 → hit; response body is parsed into HermodResult with IsThreat=true.
//   - 404 → miss; HermodResult{IsThreat:false, Address:...} is returned. This
//     is NOT cached anywhere: a miss is only valid at this moment.
//   - anything else → error.
func (c *HermodClient) CheckAddress(ctx context.Context, address string) (*HermodResult, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, fmt.Errorf("address is required")
	}
	if len(c.hmacKey) == 0 {
		return nil, fmt.Errorf("hermod HMAC key is not configured")
	}

	sig := c.SignAddress(address)
	url := fmt.Sprintf("%s/addresses/%s", c.baseURL, sig)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Hit — parse the enrichment payload.
		var body struct {
			ID                  int64  `json:"id"`
			ThreatLevel         int    `json:"threat_level"`
			HitUUID             string `json:"hit_uuid"`
			HashedAddress       string `json:"hashed_address"`
			HashedInvestigation string `json:"hashed_investigation"`
			Sanctioned          string `json:"sanctioned"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return nil, fmt.Errorf("decoding hermod hit response: %w", err)
		}
		return &HermodResult{
			Address:             address,
			IsThreat:            true,
			ID:                  body.ID,
			ThreatLevel:         body.ThreatLevel,
			HitUUID:             body.HitUUID,
			HashedAddress:       body.HashedAddress,
			HashedInvestigation: body.HashedInvestigation,
			Sanctioned:          body.Sanctioned,
		}, nil

	case http.StatusNotFound:
		// Miss — Hermod does not know about this address right now.
		// Deliberately do not cache this outcome; screening must run per-tx.
		// Drain the body so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		return &HermodResult{
			Address:  address,
			IsThreat: false,
		}, nil

	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("hermod returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
}

// CheckHealth queries Hermod's GET /up.json endpoint.
// Returns nil if Hermod is synced (HTTP 200), an error otherwise.
// Hermod returns 500 while its initial sync is pending.
func (c *HermodClient) CheckHealth(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/up.json", nil)
	if err != nil {
		return fmt.Errorf("building health request: %w", err)
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("hermod health request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("hermod not ready: status %d", resp.StatusCode)
	}
	return nil
}
