// Package main demonstrates post-quantum cryptographic algorithms for CBOM scanner testing.
// Includes ML-KEM-768 (CRYSTALS-Kyber), ML-DSA-65 (CRYSTALS-Dilithium), and SLH-DSA (SPHINCS+).
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"filippo.io/mlkem768"
)

// mlkem768Demo demonstrates key encapsulation using ML-KEM-768 (FIPS 203 / CRYSTALS-Kyber Level 3).
func mlkem768Demo() {
	// Generate a recipient key pair
	dk, err := mlkem768.GenerateKey()
	if err != nil {
		log.Fatalf("ML-KEM-768 keygen: %v", err)
	}

	ek := dk.EncapsulationKey()

	// Sender encapsulates a shared secret
	sharedSecretSender, ciphertext, err := ek.Encapsulate()
	if err != nil {
		log.Fatalf("ML-KEM-768 encapsulate: %v", err)
	}

	// Recipient decapsulates
	sharedSecretRecipient, err := dk.Decapsulate(ciphertext)
	if err != nil {
		log.Fatalf("ML-KEM-768 decapsulate: %v", err)
	}

	match := string(sharedSecretSender) == string(sharedSecretRecipient)
	fmt.Printf("ML-KEM-768: shared secret match=%v, ciphertext_len=%d\n", match, len(ciphertext))
}

// mlDSA65Stub stubs ML-DSA-65 (CRYSTALS-Dilithium security level 3 / FIPS 204) usage.
// A full implementation requires cloudflare/circl or a compatible library.
// The stub records the algorithm identifiers expected by CBOM scanners.
func mlDSA65Stub() {
	// Algorithm identifier as referenced in NIST FIPS 204
	const algorithmOID = "2.16.840.1.101.3.4.3.18" // ML-DSA-65

	// Key size constants per FIPS 204 Table 1 (level 3)
	const (
		publicKeySize  = 1952 // bytes
		privateKeySize = 4032 // bytes
		signatureSize  = 3309 // bytes
	)

	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("ML-DSA-65 seed: %v", err)
	}

	fmt.Printf("ML-DSA-65 (FIPS 204) OID=%s pk=%dB sk=%dB sig=%dB seed=%x\n",
		algorithmOID, publicKeySize, privateKeySize, signatureSize, seed[:8])
}

// slhDSAStub stubs SLH-DSA (SPHINCS+ / FIPS 205) usage.
// Demonstrates the algorithm identifiers and parameter sets expected by CBOM scanners.
func slhDSAStub() {
	// SLH-DSA parameter sets per NIST FIPS 205
	parameterSets := []struct {
		name           string
		oid            string
		publicKeySize  int
		privateKeySize int
		signatureSize  int
	}{
		{
			name:           "SLH-DSA-SHA2-128s",
			oid:            "2.16.840.1.101.3.4.3.20",
			publicKeySize:  32,
			privateKeySize: 64,
			signatureSize:  7856,
		},
		{
			name:           "SLH-DSA-SHA2-192f",
			oid:            "2.16.840.1.101.3.4.3.24",
			publicKeySize:  48,
			privateKeySize: 96,
			signatureSize:  35664,
		},
		{
			name:           "SLH-DSA-SHA2-256s",
			oid:            "2.16.840.1.101.3.4.3.27",
			publicKeySize:  64,
			privateKeySize: 128,
			signatureSize:  29792,
		},
	}

	seed := make([]byte, 32)
	rand.Read(seed) //nolint:errcheck

	for _, ps := range parameterSets {
		fmt.Printf("SLH-DSA param_set=%s oid=%s pk=%dB sk=%dB sig=%dB\n",
			ps.name, ps.oid, ps.publicKeySize, ps.privateKeySize, ps.signatureSize)
	}
}

// Note: main() is defined in crypto_samples.go; these functions are called from there.
// To run pqc_samples standalone, rename package or add build tag.

func init() {
	fmt.Println("=== Post-Quantum Cryptography Samples ===")
	mlkem768Demo()
	mlDSA65Stub()
	slhDSAStub()
}
