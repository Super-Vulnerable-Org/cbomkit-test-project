// Package main demonstrates various cryptographic algorithms for CBOM scanner testing.
// This file intentionally uses both strong and legacy algorithms to exercise scanner coverage.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"  //nolint:gosec // intentional legacy usage for CBOM testing
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"

	"golang.org/x/crypto/chacha20poly1305"
)

// aesgcmEncrypt encrypts plaintext using AES-256-GCM.
func aesgcmEncrypt(key, plaintext, additionalData []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key) // key must be 32 bytes for AES-256
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	return nonce, ciphertext, nil
}

// aescbcEncrypt encrypts plaintext using AES-128-CBC with PKCS#7 padding.
func aescbcEncrypt(key, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key) // key must be 16 bytes for AES-128
	if err != nil {
		return nil, nil, err
	}
	// Pad plaintext to block size
	blockSize := block.BlockSize()
	padding := blockSize - len(plaintext)%blockSize
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	iv := make([]byte, blockSize)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(padded))
	mode.CryptBlocks(ciphertext, padded)
	return iv, ciphertext, nil
}

// generateRSA2048 generates an RSA-2048 key pair.
func generateRSA2048() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// generateRSA4096 generates an RSA-4096 key pair.
func generateRSA4096() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

// generateEd25519 generates an Ed25519 key pair.
func generateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// generateECDSAP256 generates an ECDSA key pair using the P-256 curve.
func generateECDSAP256() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// hashSHA256 returns the SHA-256 digest of data.
func hashSHA256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// hashSHA512 returns the SHA-512 digest of data.
func hashSHA512(data []byte) []byte {
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}

// hashSHA1 returns the SHA-1 digest of data (legacy, included for CBOM coverage).
func hashSHA1(data []byte) []byte { //nolint:gosec
	h := sha1.New() //nolint:gosec
	h.Write(data)
	return h.Sum(nil)
}

// hmacSHA256 computes HMAC-SHA256 over data with key.
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// chacha20Encrypt encrypts plaintext using ChaCha20-Poly1305 (AEAD).
func chacha20Encrypt(key, plaintext, additionalData []byte) ([]byte, []byte, error) {
	aead, err := chacha20poly1305.New(key) // key must be 32 bytes
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)
	return nonce, ciphertext, nil
}

// newTLSClient returns an *http.Client configured for TLS 1.2+ with a custom CA pool.
func newTLSClient(caCertPEM []byte) (*http.Client, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caCertPEM); !ok {
		return nil, fmt.Errorf("failed to parse CA cert")
	}
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// pemEncodePublicKey serialises an RSA public key as PEM.
func pemEncodePublicKey(pub *rsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func main() {
	// AES-256-GCM
	gcmKey := make([]byte, 32)
	rand.Read(gcmKey) //nolint:errcheck
	nonce, ct, err := aesgcmEncrypt(gcmKey, []byte("hello aes-gcm"), []byte("aad"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("AES-256-GCM nonce=%x ciphertext=%x\n", nonce, ct)

	// AES-128-CBC
	cbcKey := make([]byte, 16)
	rand.Read(cbcKey) //nolint:errcheck
	iv, ct2, err := aescbcEncrypt(cbcKey, []byte("hello aes-cbc"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("AES-128-CBC iv=%x ciphertext=%x\n", iv, ct2)

	// RSA-2048
	rsaKey2048, err := generateRSA2048()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RSA-2048 generated, n.BitLen=%d\n", rsaKey2048.N.BitLen())

	// RSA-4096
	rsaKey4096, err := generateRSA4096()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("RSA-4096 generated, n.BitLen=%d\n", rsaKey4096.N.BitLen())

	// Ed25519
	edPub, _, err := generateEd25519()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Ed25519 public key len=%d\n", len(edPub))

	// ECDSA P-256
	ecKey, err := generateECDSAP256()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ECDSA P-256 key curve=%s\n", ecKey.Curve.Params().Name)

	// SHA-256 / SHA-512 / SHA-1
	msg := []byte("cbom test message")
	fmt.Printf("SHA-256=%x\n", hashSHA256(msg))
	fmt.Printf("SHA-512=%x\n", hashSHA512(msg))
	fmt.Printf("SHA-1  =%x (legacy)\n", hashSHA1(msg))

	// HMAC-SHA256
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey) //nolint:errcheck
	fmt.Printf("HMAC-SHA256=%x\n", hmacSHA256(hmacKey, msg))

	// ChaCha20-Poly1305
	cc20Key := make([]byte, 32)
	rand.Read(cc20Key) //nolint:errcheck
	ccNonce, ccCt, err := chacha20Encrypt(cc20Key, msg, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("ChaCha20-Poly1305 nonce=%x ct=%x\n", ccNonce, ccCt)

	// TLS client (TLS 1.2 minimum)
	_, err = newTLSClient(nil)
	if err != nil {
		fmt.Printf("TLS client (no CA): %v\n", err)
	} else {
		fmt.Println("TLS 1.2 client configured")
	}
}
