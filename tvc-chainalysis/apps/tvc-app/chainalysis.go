package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// caCertsPEM is the CA trust bundle compiled into the binary. Trust roots are
// embedded rather than read from the container filesystem so the app is fully
// self-contained: the exact CA set is part of the attested pivot binary digest,
// and TLS verification doesn't depend on ambient system trust. The static
// (CGO_ENABLED=0) binary runs on a minimal image that ships no system trust
// store, so there is no /etc/ssl/certs to read at runtime by design.
//
//go:embed ca-certificates.crt
var caCertsPEM []byte

// Identification represents a single sanctions match returned by Chainalysis.
type Identification struct {
	Category    string `json:"category"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// chainalysisResponse mirrors the Chainalysis Sanctions API response body.
type chainalysisResponse struct {
	Identifications []Identification `json:"identifications"`
}

// ChainalysisClient is a thin wrapper around the Chainalysis Sanctions API.
type ChainalysisClient struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewChainalysisClient creates a client using the provided API key. It verifies
// TLS against the embedded CA bundle only (see caCertsPEM), so it does not rely
// on system certificates being present in the enclave image.
func NewChainalysisClient(apiKey string) *ChainalysisClient {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertsPEM) {
		// The bundle is baked in at build time; a parse failure means the build
		// is broken, so fail loudly rather than silently falling back to no roots.
		panic("tvc-app: failed to parse embedded CA bundle (ca-certificates.crt)")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}

	return &ChainalysisClient{
		apiKey:  apiKey,
		baseURL: "https://public.chainalysis.com",
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
		},
	}
}

// CheckAddress queries the Chainalysis Sanctions API for the given address.
// Returns the raw API response; an empty Identifications slice means clean.
func (c *ChainalysisClient) CheckAddress(ctx context.Context, address string) (*chainalysisResponse, error) {
	url := fmt.Sprintf("%s/api/v1/address/%s", c.baseURL, address)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("invalid address format")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("chainalysis API returned status %d", resp.StatusCode)
	}

	var result chainalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Normalize a nil slice to an empty one so it marshals to a JSON array
	// (`[]`) rather than `null`, keeping the API response shape stable for
	// clients regardless of whether the address had any identifications.
	if result.Identifications == nil {
		result.Identifications = []Identification{}
	}

	return &result, nil
}
