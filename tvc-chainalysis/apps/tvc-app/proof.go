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
//   https://docs.rs/qos_p256/0.10.2/qos_p256/constant.P256_SIGN_DERIVE_PATH.html
//   https://docs.rs/qos_p256/0.10.2/qos_p256/constant.P256_ENCRYPT_DERIVE_PATH.html
var p256SignDerivePath = []byte("qos_p256_sign")
var p256EncryptDerivePath = []byte("qos_p256_encrypt")

// AppProof is a P-256 signature by the enclave Ephemeral Key over a typed payload.
type AppProof struct {
	Scheme       string `json:"scheme"`
	PublicKey    string `json:"publicKey"`
	ProofPayload string `json:"proofPayload"`
	Signature    string `json:"signature"`
}

type proofPayload struct {
	Type           string             `json:"type"`
	TimestampMs    string             `json:"timestampMs"`
	SanctionsCheck sanctionsCheckData `json:"sanctionsCheckProof"`
}

type sanctionsCheckData struct {
	Address         string           `json:"address"`
	Sanctioned      bool             `json:"sanctioned"`
	Identifications []Identification `json:"identifications"`
}

// loadEphemeralSigningKey reads the QOS ephemeral key file and derives the P-256 signing key
// via HKDF-SHA512(ikm=masterSeed, salt="qos_p256_sign", info=nil).
// Also returns the raw master seed for use with buildBootEphemeralKey.
// Returns (nil, nil, nil) if the file doesn't exist (e.g. running outside an enclave).
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

// signScreening produces an App Proof for a sanctions screening result.
// Returns nil if no signing key is available.
func signScreening(privKey *ecdsa.PrivateKey, address string, sanctioned bool, identifications []Identification) (*AppProof, error) {
	if privKey == nil {
		return nil, nil
	}
	if identifications == nil {
		identifications = []Identification{}
	}

	payload := proofPayload{
		Type:        "APP_PROOF_TYPE_SANCTIONS_SCREENING",
		TimestampMs: fmt.Sprintf("%d", time.Now().UnixMilli()),
		SanctionsCheck: sanctionsCheckData{
			Address:         address,
			Sanctioned:      sanctioned,
			Identifications: identifications,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling proof payload: %w", err)
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
