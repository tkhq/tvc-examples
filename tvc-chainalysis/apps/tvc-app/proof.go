package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

const ephemeralKeyFile = "/qos.ephemeral.key"

// QOS derive paths — must match the qos_p256 crate constants:
//
//	https://docs.rs/qos_p256/0.10.2/qos_p256/constant.P256_SIGN_DERIVE_PATH.html
//	https://docs.rs/qos_p256/0.10.2/qos_p256/constant.P256_ENCRYPT_DERIVE_PATH.html
var p256SignDerivePath = []byte("qos_p256_sign")
var p256EncryptDerivePath = []byte("qos_p256_encrypt")

// AppProof is a P-256 signature by the enclave Ephemeral Key over a typed payload.
type AppProof struct {
	Scheme       string `json:"scheme"`
	PublicKey    string `json:"publicKey"`
	ProofPayload string `json:"proofPayload"`
	Signature    string `json:"signature"`
}

// hermodProofPayload is the typed envelope signed by the enclave's ephemeral
// key. The core signing pipeline (P-256 key, SHA-256 digest, ASN.1 DER
// signature) is the same as in the original Chainalysis-based example, so
// the in-browser verifier does not need a separate code path — only the
// payload shape changed.
type hermodProofPayload struct {
	Type        string                `json:"type"`
	TimestampMs string                `json:"timestampMs"`
	ThreatCheck hermodThreatCheckData `json:"threatCheckProof"`
}

type hermodThreatCheckData struct {
	Address             string `json:"address"`
	IsThreat            bool   `json:"isThreat"`
	ThreatLevel         int    `json:"threatLevel,omitempty"`
	HitUUID             string `json:"hitUuid,omitempty"`
	HashedInvestigation string `json:"hashedInvestigation,omitempty"`
	Sanctioned          string `json:"sanctioned,omitempty"`
}

// loadEphemeralSigningKey reads the QOS ephemeral key file and derives the P-256 signing key
// via HKDF-SHA512(ikm=masterSeed, salt="qos_p256_sign", info=nil).
// Also returns the raw master seed for use with buildBootEphemeralKey.
//
// A missing key file is not treated as an error: it returns (nil, nil, nil).
// The file only exists inside the enclave, so when running locally (or anywhere
// outside TVC) the app is expected to start without it and simply serve
// screening results with no app proof. The caller checks for a nil key and logs
// a warning rather than failing. Any other read/parse failure IS returned as an
// error, since that indicates a genuinely malformed key rather than its absence.
func loadEphemeralSigningKey() (*ecdsa.PrivateKey, []byte, error) {
	data, err := os.ReadFile(ephemeralKeyFile)
	if os.IsNotExist(err) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("reading %s: %w", ephemeralKeyFile, err)
	}

	masterSeed, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, nil, fmt.Errorf("hex-decoding master seed: %w", err)
	}
	if len(masterSeed) != 32 {
		return nil, nil, fmt.Errorf("expected 32-byte master seed, got %d", len(masterSeed))
	}

	signSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, masterSeed, p256SignDerivePath, nil), signSecret); err != nil {
		return nil, nil, fmt.Errorf("deriving sign secret: %w", err)
	}

	curve := elliptic.P256()
	privKey := new(ecdsa.PrivateKey)
	privKey.PublicKey.Curve = curve
	privKey.D = new(big.Int).SetBytes(signSecret)
	privKey.PublicKey.X, privKey.PublicKey.Y = curve.ScalarBaseMult(signSecret)

	return privKey, masterSeed, nil
}

// buildBootEphemeralKey constructs the QOS KeySet hex used to look up the boot proof:
// encryptPub (65 bytes) + signPub (65 bytes) = 130 bytes total.
func buildBootEphemeralKey(masterSeed []byte) (string, error) {
	curve := elliptic.P256()

	encryptSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, masterSeed, p256EncryptDerivePath, nil), encryptSecret); err != nil {
		return "", fmt.Errorf("deriving encrypt secret: %w", err)
	}
	ex, ey := curve.ScalarBaseMult(encryptSecret)
	encryptPub := make([]byte, 65)
	encryptPub[0] = 0x04
	ex.FillBytes(encryptPub[1:33])
	ey.FillBytes(encryptPub[33:65])

	signSecret := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha512.New, masterSeed, p256SignDerivePath, nil), signSecret); err != nil {
		return "", fmt.Errorf("deriving sign secret: %w", err)
	}
	sx, sy := curve.ScalarBaseMult(signSecret)
	signPub := make([]byte, 65)
	signPub[0] = 0x04
	sx.FillBytes(signPub[1:33])
	sy.FillBytes(signPub[33:65])

	return hex.EncodeToString(append(encryptPub, signPub...)), nil
}

// signHermodScreening produces an App Proof for a Hermod threat screening.
// Returns nil if no signing key is available (e.g. running outside a Nitro
// Enclave with no /qos.ephemeral.key file). Errors from marshaling, digest,
// or signing are surfaced as-is.
func signHermodScreening(privKey *ecdsa.PrivateKey, res *HermodResult) (*AppProof, error) {
	if privKey == nil {
		return nil, nil
	}
	if res == nil {
		return nil, fmt.Errorf("cannot sign a nil hermod result")
	}

	payload := hermodProofPayload{
		Type:        "APP_PROOF_TYPE_THREAT_SCREENING",
		TimestampMs: fmt.Sprintf("%d", time.Now().UnixMilli()),
		ThreatCheck: hermodThreatCheckData{
			Address:             res.Address,
			IsThreat:            res.IsThreat,
			ThreatLevel:         res.ThreatLevel,
			HitUUID:             res.HitUUID,
			HashedInvestigation: res.HashedInvestigation,
			Sanctioned:          res.Sanctioned,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling hermod proof payload: %w", err)
	}

	digest := sha256.Sum256(payloadBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	// Uncompressed SEC1 public key: 04 || X (32 bytes) || Y (32 bytes)
	pubKeyBytes := make([]byte, 65)
	pubKeyBytes[0] = 0x04
	privKey.PublicKey.X.FillBytes(pubKeyBytes[1:33])
	privKey.PublicKey.Y.FillBytes(pubKeyBytes[33:65])

	return &AppProof{
		Scheme:       "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
		PublicKey:    hex.EncodeToString(pubKeyBytes),
		ProofPayload: string(payloadBytes),
		Signature:    hex.EncodeToString(sig),
	}, nil
}
