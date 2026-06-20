package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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

// mockedAddresses short-circuits the Chainalysis API call for known test
// addresses so the enclave (which has no external network access) can still
// return realistic results during demos.
var mockedAddresses = map[string]*chainalysisResponse{
	"0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a": {
		Identifications: []Identification{
			{
				Category: "sanctioned entity",
				Name:     "SANCTIONED ENTITY: OFAC SDN Secondeye Solution 2021-04-15 1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
				Description: "Pakistan-based Secondeye Solution (SES), also known as Forwarderz, is a synthetic identity document vendor that was added to the OFAC SDN list in April 2021.\n\n" +
					"SES customers could buy fake identity documents to sign up for accounts with cryptocurrency exchanges, payment providers, banks, and more under false identities. " +
					"According to the US Treasury Department, SES assisted the Internet Research Agency (IRA), the Russian troll farm that OFAC designated pursuant to E.O. 13848 in 2018 " +
					"for interfering in the 2016 presidential election, in concealing its identity to evade sanctions.\n\nhttps://home.treasury.gov/news/press-releases/jy0126",
				URL: "https://home.treasury.gov/news/press-releases/jy0126",
			},
			{
				Category: "sanctions",
				Name:     "SANCTIONS: OFAC SDN Secondeye Solution 2021-04-15 1da5821544e25c636c1417ba96ade4cf6d2f9b5a",
				Description: "Pakistan-based Secondeye Solution (SES), also known as Forwarderz, is a synthetic identity document vendor that was added to the OFAC SDN list in April 2021.\n\n" +
					"SES customers could buy fake identity documents to sign up for accounts with cryptocurrency exchanges, payment providers, banks, and more under false identities. " +
					"According to the US Treasury Department, SES assisted the Internet Research Agency (IRA), the Russian troll farm that OFAC designated pursuant to E.O. 13848 in 2018 " +
					"for interfering in the 2016 presidential election, in concealing its identity to evade sanctions.\n\nhttps://home.treasury.gov/news/press-releases/jy0126",
				URL: "https://home.treasury.gov/news/press-releases/jy0126",
			},
		},
	},
	"0xffc93b73e5f9fa038598b675ed394faed168688b": {
		Identifications: []Identification{},
	},
}

// CheckAddress queries the Chainalysis Sanctions API for the given address.
// Returns the raw API response; an empty Identifications slice means clean.
func (c *ChainalysisClient) CheckAddress(ctx context.Context, address string) (*chainalysisResponse, error) {
	if mocked, ok := mockedAddresses[strings.ToLower(address)]; ok {
		return mocked, nil
	}

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

	return &result, nil
}
