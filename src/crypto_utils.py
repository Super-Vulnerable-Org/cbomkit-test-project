"""
crypto_utils.py — Cryptographic utility functions for CBOM scanner testing.

Exercises the following algorithms via the `cryptography` library:
  - AES-256-GCM (symmetric AEAD encryption)
  - RSA-2048 signing with PSS / PKCS1v15
  - SHA-256 hashing
  - X.509 certificate loading and inspection
  - ssl.SSLContext with TLS 1.2/1.3 configuration
"""

from __future__ import annotations

import hashlib
import os
import ssl
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ---------------------------------------------------------------------------
# AES-256-GCM
# ---------------------------------------------------------------------------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Args:
        key: 32-byte key.
        plaintext: Data to encrypt.
        aad: Additional authenticated data (not encrypted).

    Returns:
        (nonce, ciphertext_with_tag) tuple.
    """
    aesgcm = AESGCM(key)  # algorithm: AES-256-GCM
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305
# ---------------------------------------------------------------------------

def chacha20_poly1305_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """Encrypt with ChaCha20-Poly1305 AEAD."""
    cc = ChaCha20Poly1305(key)  # algorithm: ChaCha20-Poly1305
    nonce = os.urandom(12)
    ciphertext = cc.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


# ---------------------------------------------------------------------------
# RSA key generation and signing
# ---------------------------------------------------------------------------

def generate_rsa_keypair(key_size: int = 2048) -> RSAPrivateKey:
    """Generate an RSA key pair of *key_size* bits."""
    from cryptography.hazmat.backends import default_backend
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,  # RSA-2048 or RSA-4096
        backend=default_backend(),
    )
    return private_key


def rsa_sign_pss(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Sign *message* using RSA-PSS with SHA-256."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),  # algorithm: SHA-256
    )
    return signature


def rsa_verify_pss(public_key: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Verify an RSA-PSS signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False


def rsa_sign_pkcs1v15(private_key: RSAPrivateKey, message: bytes) -> bytes:
    """Sign *message* using RSASSA-PKCS1-v1_5 with SHA-256 (legacy)."""
    return private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )


# ---------------------------------------------------------------------------
# ECDSA (P-256)
# ---------------------------------------------------------------------------

def generate_ec_keypair() -> ec.EllipticCurvePrivateKey:
    """Generate an ECDSA P-256 key pair."""
    return ec.generate_private_key(ec.SECP256R1())  # curve: P-256


def ecdsa_sign(private_key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    """Sign *message* with ECDSA using SHA-256."""
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


# ---------------------------------------------------------------------------
# SHA-256 hashing (stdlib and cryptography library)
# ---------------------------------------------------------------------------

def sha256_hash(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data*."""
    digest = hashes.Hash(hashes.SHA256())  # algorithm: SHA-256
    digest.update(data)
    return digest.finalize()


def sha256_stdlib(data: bytes) -> bytes:
    """Return SHA-256 using the stdlib hashlib (also tagged by scanners)."""
    return hashlib.sha256(data).digest()  # algorithm: SHA-256


def sha512_hash(data: bytes) -> bytes:
    """Return the SHA-512 digest of *data*."""
    digest = hashes.Hash(hashes.SHA512())  # algorithm: SHA-512
    digest.update(data)
    return digest.finalize()


def md5_hash(data: bytes) -> bytes:  # noqa: S324
    """Return MD5 digest (legacy — included for CBOM weak-algorithm coverage)."""
    return hashlib.md5(data).digest()  # noqa: S324  # algorithm: MD5


# ---------------------------------------------------------------------------
# HMAC-SHA256
# ---------------------------------------------------------------------------

def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Compute HMAC-SHA256 over *message* using *key*."""
    h = hmac.HMAC(key, hashes.SHA256())  # algorithm: HMAC-SHA256
    h.update(message)
    return h.finalize()


# ---------------------------------------------------------------------------
# PBKDF2 key derivation
# ---------------------------------------------------------------------------

def derive_key_pbkdf2(password: bytes, salt: bytes, iterations: int = 600_000) -> bytes:
    """Derive a 32-byte key from *password* using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # algorithm: SHA-256
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password)


# ---------------------------------------------------------------------------
# X.509 certificate inspection
# ---------------------------------------------------------------------------

def load_certificate_pem(pem_data: bytes):
    """Load and return an X.509 certificate from PEM-encoded bytes."""
    cert = load_pem_x509_certificate(pem_data)  # X.509 parsing
    subject_cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    sig_alg = cert.signature_hash_algorithm
    return {
        "subject_cn": subject_cn[0].value if subject_cn else None,
        "serial": cert.serial_number,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "signature_algorithm": sig_alg.name if sig_alg else "unknown",
        "public_key_size": cert.public_key().key_size,
    }


def inspect_certificate_file(path: str) -> dict:
    """Load a PEM certificate from *path* and return a summary dict."""
    with open(path, "rb") as fh:
        return load_certificate_pem(fh.read())


# ---------------------------------------------------------------------------
# ssl.SSLContext configuration
# ---------------------------------------------------------------------------

def create_tls_client_context(
    cafile: Optional[str] = None,
    certfile: Optional[str] = None,
    keyfile: Optional[str] = None,
) -> ssl.SSLContext:
    """Build an ssl.SSLContext for TLS client use (TLS 1.2 minimum)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # protocol: TLS
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # min: TLS 1.2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3   # max: TLS 1.3
    ctx.set_ciphers(
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384"
    )
    if cafile:
        ctx.load_verify_locations(cafile=cafile)
    if certfile and keyfile:
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


def create_tls_server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Build an ssl.SSLContext for TLS server use."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return ctx


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def private_key_to_pem(private_key) -> bytes:
    """Serialise a private key to PKCS#8 PEM (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> bytes:
    """Serialise a public key to SubjectPublicKeyInfo PEM."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


# ---------------------------------------------------------------------------
# Demo / smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # AES-256-GCM round-trip
    key = os.urandom(32)
    nonce, ct = aes_gcm_encrypt(key, b"hello aes-gcm", b"aad")
    pt = aes_gcm_decrypt(key, nonce, ct, b"aad")
    assert pt == b"hello aes-gcm"
    print(f"AES-256-GCM OK  ciphertext={ct.hex()[:32]}…")

    # RSA-2048 sign/verify
    rsa_key = generate_rsa_keypair(2048)
    msg = b"cbom scanner test message"
    sig = rsa_sign_pss(rsa_key, msg)
    ok = rsa_verify_pss(rsa_key.public_key(), msg, sig)
    print(f"RSA-2048 PSS sign/verify={ok}")

    # SHA-256
    digest = sha256_hash(msg)
    print(f"SHA-256={digest.hex()}")

    # HMAC-SHA256
    hkey = os.urandom(32)
    mac = hmac_sha256(hkey, msg)
    print(f"HMAC-SHA256={mac.hex()}")

    # PBKDF2
    dk = derive_key_pbkdf2(b"password", os.urandom(16))
    print(f"PBKDF2-HMAC-SHA256 derived key={dk.hex()[:16]}…")

    # TLS context
    ctx = create_tls_client_context()
    print(f"TLS client context min_version={ctx.minimum_version}")

    # Certificate (try loading from local certs dir if present)
    cert_path = Path(__file__).parent.parent / "certs" / "server.crt"
    if cert_path.exists():
        info = inspect_certificate_file(str(cert_path))
        print(f"Certificate: CN={info['subject_cn']} alg={info['signature_algorithm']} keysize={info['public_key_size']}")
