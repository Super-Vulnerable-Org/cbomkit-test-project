# cbomkit-test-project   

A synthetic test repository containing intentionally diverse cryptographic assets for validating **CBOM (Cryptographic Bill of Materials) scanner** coverage across all detection categories.

> **Warning:** This repository is a **test fixture only**. Private keys and certificates are generated solely for scanner testing. Never use these credentials in production.

---

## Purpose

Running a CBOM scanner (e.g., IBM CBOMkit, CycloneDX Cryptography Scanner) against this repository should produce findings across **all** detection categories:

| Category | Expected Findings |
|---|---|
| Algorithms | AES-256-GCM, AES-128-CBC, RSA-2048/4096, Ed25519, ECDSA P-256, SHA-256, SHA-512, SHA-1, HMAC-SHA256, ChaCha20-Poly1305, MD5, RC4 (weak) |
| Post-Quantum | ML-KEM-768, ML-DSA-65, SLH-DSA |
| Certificates | server.crt (RSA-2048, SHA-256), ca.crt (RSA-4096, SHA-384) |
| Keys / Secrets | RSA-2048 PKCS#8 private key, EC P-256 private key |
| Libraries | Go stdlib crypto, filippo.io/mlkem768, golang.org/x/crypto, Python cryptography, Java javax.crypto |
| Databases | PostgreSQL (sslmode=require), MySQL (ssl-mode=REQUIRED), Redis (TLS) |
| Services | nginx TLS 1.2/1.3, sshd (strong + weak KexAlgorithms) |
| OpenSSL Configs | MinProtocol=TLSv1.2, CipherString=DEFAULT:@SECLEVEL=1 |

---

## Repository Layout

```
cbomkit-test-project/
├── src/
│   ├── crypto_samples.go    # Go: AES-GCM, AES-CBC, RSA, Ed25519, ECDSA, SHA-*, HMAC, ChaCha20, TLS client
│   ├── pqc_samples.go       # Go: ML-KEM-768, ML-DSA-65, SLH-DSA stubs
│   ├── crypto_utils.py      # Python: AES-GCM, RSA-PSS, ECDSA, SHA-256, X.509, ssl.SSLContext
│   └── CryptoUtils.java     # Java: javax.crypto AES-CBC/GCM, RSA, ECDSA, MessageDigest, SSLContext, KeyStore
├── certs/
│   ├── server.crt           # RSA-2048, SHA-256, SANs, not a CA
│   └── ca.crt               # RSA-4096, SHA-384, isCA=true
├── keys/
│   ├── private.key          # RSA-2048 PKCS#8 PEM
│   └── ec_private.key       # EC P-256 PKCS#8 PEM
├── configs/
│   ├── nginx.conf           # TLS 1.2/1.3, weak RC4 cipher entry, HSTS
│   ├── sshd_config          # Strong + weak KEX (diffie-hellman-group1-sha1, arcfour)
│   ├── openssl.cnf          # MinProtocol=TLSv1.2, CipherString=DEFAULT:@SECLEVEL=1
│   └── database.yml         # PostgreSQL, MySQL, Redis — all with TLS cert paths
├── docker-compose.yml       # postgres + mysql + redis with SSL env vars and cert mounts
├── go.mod                   # filippo.io/mlkem768, golang.org/x/crypto
└── README.md
```

---

## Intentional Weak / Legacy Algorithms (for Scanner Detection)

The following weak algorithms are included **on purpose** to verify CBOM scanners flag them:

- **RC4** — nginx `ssl_ciphers` and SSH `Ciphers` (arcfour)
- **SHA-1** — Go and Java source, SSH `HostKeyAlgorithms` (ssh-rsa)
- **MD5** — Java `MessageDigest.getInstance("MD5")`, Python `hashlib.md5`
- **diffie-hellman-group1-sha1** — sshd `KexAlgorithms`
- **3DES-CBC** — SSH `Ciphers`
- **TLS 1.2 minimum** (TLS 1.0/1.1 excluded but TLS 1.2 is still legacy in some profiles)
- **SECLEVEL=1** — openssl.cnf `CipherString`

---

## Running a CBOM Scan (example)

```bash
# IBM CBOMkit (if available)
cbomkit scan --output cbom.json .

# CycloneDX crypto scanner
cyclonedx-crypto-scanner --dir . --output bom.json
```
