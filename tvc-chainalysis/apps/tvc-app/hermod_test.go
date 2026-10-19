package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSignAddress_KnownVector locks in the HMAC-SHA256 test vector from
// Hermod's own documentation. If this test fails, the client is generating
// signatures that Hermod cannot match, and every lookup will look like a
// miss regardless of the real threat status. This is the single hardest
// correctness assertion for the client.
//
// Vector:
//   address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" (Bitcoin genesis coinbase)
//   key     = "key"
//   expect  = fc1c0060a3158f2b690ed2e5faa5a6a324276a2c162505e91a14b7baf1419e05
func TestSignAddress_KnownVector(t *testing.T) {
	got := signAddress("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", []byte("key"))
	const want = "fc1c0060a3158f2b690ed2e5faa5a6a324276a2c162505e91a14b7baf1419e05"
	if got != want {
		t.Fatalf("HMAC-SHA256 signature mismatch\n  got:  %s\n  want: %s", got, want)
	}
}

// TestSignAddress_EVMLowercaseVsChecksum documents that Hermod treats
// lowercase and checksummed EVM addresses as distinct inputs — different
// bytes go into the HMAC, so different signatures come out. The Hermod
// spec allows signing either form; the client just has to be consistent.
func TestSignAddress_EVMLowercaseVsChecksum(t *testing.T) {
	key := []byte("some-per-account-key")
	lower := signAddress("0x1da5821544e25c636c1417ba96ade4cf6d2f9b5a", key)
	checksummed := signAddress("0x1dA5821544E25c636c1417bA96Ade4cF6d2f9b5a", key)
	if lower == checksummed {
		t.Fatalf("expected different HMACs for lowercase vs checksummed EVM address; both were %s", lower)
	}
}

// TestCheckAddress_Hit verifies the client parses a 200 hit body into a
// HermodResult with IsThreat=true and populated enrichment fields.
func TestCheckAddress_Hit(t *testing.T) {
	address := "0xdeadbeef00000000000000000000000000000000"
	hmacKey := "test-key"
	wantSig := signAddress(address, []byte(hmacKey))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/addresses/"+wantSig) {
			t.Errorf("expected path to end with /addresses/%s, got %s", wantSig, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":                   42,
			"threat_level":         9,
			"hit_uuid":             "abcd-1234",
			"hashed_address":       wantSig,
			"hashed_investigation": "investigation-hash",
			"sanctioned":           "OFAC",
		})
	}))
	defer srv.Close()

	client := NewHermodClient(srv.URL, hmacKey, "")
	res, err := client.CheckAddress(context.Background(), address)
	if err != nil {
		t.Fatalf("CheckAddress error: %v", err)
	}
	if !res.IsThreat {
		t.Fatalf("expected IsThreat=true, got false")
	}
	if res.ThreatLevel != 9 {
		t.Errorf("ThreatLevel: got %d, want 9", res.ThreatLevel)
	}
	if res.HitUUID != "abcd-1234" {
		t.Errorf("HitUUID: got %q, want abcd-1234", res.HitUUID)
	}
	if res.HashedAddress != wantSig {
		t.Errorf("HashedAddress echo: got %q, want %q", res.HashedAddress, wantSig)
	}
	if res.HashedInvestigation != "investigation-hash" {
		t.Errorf("HashedInvestigation: got %q, want investigation-hash", res.HashedInvestigation)
	}
	if res.Sanctioned != "OFAC" {
		t.Errorf("Sanctioned: got %q, want OFAC", res.Sanctioned)
	}
	if res.Address != address {
		t.Errorf("Address: got %q, want %q", res.Address, address)
	}
}

// TestCheckAddress_Miss verifies a 404 becomes IsThreat=false with zero
// enrichment fields, and the "never cache a miss" invariant depends on
// callers not persisting this response.
func TestCheckAddress_Miss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	client := NewHermodClient(srv.URL, "test-key", "")
	res, err := client.CheckAddress(context.Background(), "0xabc")
	if err != nil {
		t.Fatalf("CheckAddress error: %v", err)
	}
	if res.IsThreat {
		t.Fatalf("expected IsThreat=false on 404, got true")
	}
	if res.ThreatLevel != 0 || res.HitUUID != "" || res.Sanctioned != "" {
		t.Errorf("expected zero enrichment fields on miss, got %+v", res)
	}
}

// TestCheckAddress_BearerAuth verifies the optional bearer token is
// forwarded to Hermod when configured.
func TestCheckAddress_BearerAuth(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	client := NewHermodClient(srv.URL, "test-key", "super-secret-bearer")
	if _, err := client.CheckAddress(context.Background(), "0xabc"); err != nil {
		t.Fatalf("CheckAddress error: %v", err)
	}
	if gotAuth != "Bearer super-secret-bearer" {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, "Bearer super-secret-bearer")
	}
}

// TestCheckAddress_UnexpectedStatus verifies any status other than 200/404
// surfaces as an error rather than being silently treated as a miss.
func TestCheckAddress_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("hermod not synced"))
	}))
	defer srv.Close()

	client := NewHermodClient(srv.URL, "test-key", "")
	_, err := client.CheckAddress(context.Background(), "0xabc")
	if err == nil {
		t.Fatalf("expected error on 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to mention status 500, got: %v", err)
	}
}
