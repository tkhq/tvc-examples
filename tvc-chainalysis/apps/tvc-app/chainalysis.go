package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

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

// NewChainalysisClient creates a client using the provided API key.
func NewChainalysisClient(apiKey string) *ChainalysisClient {
	return &ChainalysisClient{
		apiKey:  apiKey,
		baseURL: "https://public.chainalysis.com",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
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
