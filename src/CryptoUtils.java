package com.example.cbomtest;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAKey;
import java.security.spec.*;
import java.util.Base64;
import javax.net.ssl.*;

/**
 * CryptoUtils — Java cryptographic primitives for CBOM scanner testing.
 *
 * <p>Exercises:
 * <ul>
 *   <li>AES/CBC/PKCS5Padding (AES-128-CBC via javax.crypto)</li>
 *   <li>AES/GCM/NoPadding  (AES-256-GCM)</li>
 *   <li>RSA KeyPair generation (2048 and 4096 bits)</li>
 *   <li>RSA-OAEP encryption / RSASSA-PSS signing</li>
 *   <li>ECDSA P-256 signing</li>
 *   <li>MessageDigest SHA-256 / SHA-512 / MD5 (legacy)</li>
 *   <li>Mac HmacSHA256</li>
 *   <li>SSLContext for TLS 1.2 and TLS 1.3</li>
 *   <li>KeyStore (PKCS12)</li>
 * </ul>
 */
public class CryptoUtils {

    // -------------------------------------------------------------------------
    // AES-128-CBC (PKCS5 padding)
    // -------------------------------------------------------------------------

    /**
     * Encrypt {@code plaintext} with AES/CBC/PKCS5Padding using {@code key}.
     *
     * @param key       16-byte AES-128 key (algorithm: AES-128-CBC)
     * @param plaintext bytes to encrypt
     * @return [iv (16 bytes) | ciphertext]
     */
    public static byte[] aesCbcEncrypt(byte[] key, byte[] plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); // algorithm: AES
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // mode: CBC, padding: PKCS5
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        AlgorithmParameters params = cipher.getParameters();
        byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return result;
    }

    // -------------------------------------------------------------------------
    // AES-256-GCM
    // -------------------------------------------------------------------------

    /**
     * Encrypt with AES/GCM/NoPadding (AES-256-GCM).
     *
     * @param key       32-byte AES-256 key
     * @param plaintext bytes to encrypt
     * @param aad       additional authenticated data (may be empty)
     * @return [nonce (12 bytes) | ciphertext+tag]
     */
    public static byte[] aesGcmEncrypt(byte[] key, byte[] plaintext, byte[] aad) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES"); // algorithm: AES-256
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // mode: GCM
        byte[] nonce = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(nonce);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce); // tag length: 128 bits
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        if (aad != null && aad.length > 0) {
            cipher.updateAAD(aad);
        }
        byte[] ciphertext = cipher.doFinal(plaintext);
        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
        return result;
    }

    // -------------------------------------------------------------------------
    // RSA Key Generation
    // -------------------------------------------------------------------------

    /**
     * Generate an RSA-2048 key pair.
     *
     * @return KeyPair with RSA algorithm, 2048-bit modulus
     */
    public static KeyPair generateRsa2048() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // algorithm: RSA
        kpg.initialize(2048, new SecureRandom()); // key size: 2048
        return kpg.generateKeyPair();
    }

    /**
     * Generate an RSA-4096 key pair.
     *
     * @return KeyPair with RSA algorithm, 4096-bit modulus
     */
    public static KeyPair generateRsa4096() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // algorithm: RSA
        kpg.initialize(4096, new SecureRandom()); // key size: 4096
        return kpg.generateKeyPair();
    }

    // -------------------------------------------------------------------------
    // RSA-OAEP Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypt with RSA-OAEP (SHA-256 hash, MGF1-SHA256 mask).
     */
    public static byte[] rsaOaepEncrypt(PublicKey publicKey, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // algorithm: RSA-OAEP
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
            "SHA-256", "MGF1",
            new MGF1ParameterSpec("SHA-256"),
            PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        return cipher.doFinal(plaintext);
    }

    // -------------------------------------------------------------------------
    // RSA-PSS Signing
    // -------------------------------------------------------------------------

    /**
     * Sign with RSASSA-PSS using SHA-256 and MGF1-SHA256.
     */
    public static byte[] rsaPssSign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature sig = Signature.getInstance("RSASSA-PSS"); // algorithm: RSA-PSS
        PSSParameterSpec pssSpec = new PSSParameterSpec(
            "SHA-256",                         // hash algorithm
            "MGF1",                            // mask generation function
            new MGF1ParameterSpec("SHA-256"),  // MGF hash
            32,                                // salt length
            1                                  // trailer field
        );
        sig.setParameter(pssSpec);
        sig.initSign(privateKey, new SecureRandom());
        sig.update(message);
        return sig.sign();
    }

    // -------------------------------------------------------------------------
    // ECDSA P-256
    // -------------------------------------------------------------------------

    /**
     * Generate an ECDSA P-256 key pair.
     */
    public static KeyPair generateEcP256() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC"); // algorithm: EC
        kpg.initialize(new ECGenParameterSpec("secp256r1")); // curve: P-256
        return kpg.generateKeyPair();
    }

    /**
     * Sign with ECDSA P-256 using SHA-256.
     */
    public static byte[] ecdsaSign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA"); // algorithm: ECDSA, hash: SHA-256
        sig.initSign(privateKey, new SecureRandom());
        sig.update(message);
        return sig.sign();
    }

    // -------------------------------------------------------------------------
    // MessageDigest
    // -------------------------------------------------------------------------

    /** SHA-256 hash. */
    public static byte[] sha256(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256"); // algorithm: SHA-256
        return md.digest(data);
    }

    /** SHA-512 hash. */
    public static byte[] sha512(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-512"); // algorithm: SHA-512
        return md.digest(data);
    }

    /** SHA-1 hash (legacy — included for CBOM weak-algorithm coverage). */
    public static byte[] sha1Legacy(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1"); // algorithm: SHA-1 (weak)
        return md.digest(data);
    }

    /** MD5 hash (legacy — included for CBOM weak-algorithm coverage). */
    public static byte[] md5Legacy(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5"); // algorithm: MD5 (weak)
        return md.digest(data);
    }

    // -------------------------------------------------------------------------
    // HMAC
    // -------------------------------------------------------------------------

    /** HMAC-SHA256 over {@code message} using {@code key}. */
    public static byte[] hmacSha256(byte[] key, byte[] message) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256"); // algorithm: HMAC-SHA256
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(message);
    }

    // -------------------------------------------------------------------------
    // SSLContext
    // -------------------------------------------------------------------------

    /**
     * Create an SSLContext configured for TLS 1.2.
     */
    public static SSLContext createTls12Context() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.2"); // protocol: TLS 1.2
        ctx.init(null, null, new SecureRandom());
        return ctx;
    }

    /**
     * Create an SSLContext configured for TLS 1.3.
     */
    public static SSLContext createTls13Context() throws Exception {
        SSLContext ctx = SSLContext.getInstance("TLSv1.3"); // protocol: TLS 1.3
        ctx.init(null, null, new SecureRandom());
        return ctx;
    }

    // -------------------------------------------------------------------------
    // KeyStore (PKCS12)
    // -------------------------------------------------------------------------

    /**
     * Create an in-memory PKCS12 KeyStore holding a key pair and its certificate.
     */
    public static KeyStore createPkcs12KeyStore(
            String alias,
            KeyPair keyPair,
            java.security.cert.Certificate cert,
            char[] password
    ) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12"); // keystore type: PKCS12
        ks.load(null, password);
        ks.setKeyEntry(alias, keyPair.getPrivate(), password,
                new java.security.cert.Certificate[]{cert});
        return ks;
    }

    // -------------------------------------------------------------------------
    // X.509 Certificate Loading
    // -------------------------------------------------------------------------

    /**
     * Load a PEM X.509 certificate.
     */
    public static X509Certificate loadX509Certificate(byte[] pemBytes) throws Exception {
        // Strip PEM headers
        String pem = new String(pemBytes, StandardCharsets.UTF_8)
            .replaceAll("-----BEGIN CERTIFICATE-----", "")
            .replaceAll("-----END CERTIFICATE-----", "")
            .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(pem);
        CertificateFactory cf = CertificateFactory.getInstance("X.509"); // format: X.509
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    // -------------------------------------------------------------------------
    // Demo / smoke-test
    // -------------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        byte[] msg = "cbom scanner test message".getBytes(StandardCharsets.UTF_8);

        // AES-128-CBC
        byte[] cbcKey = new byte[16];
        new SecureRandom().nextBytes(cbcKey);
        byte[] cbcResult = aesCbcEncrypt(cbcKey, msg);
        System.out.printf("AES-128-CBC encrypted len=%d%n", cbcResult.length);

        // AES-256-GCM
        byte[] gcmKey = new byte[32];
        new SecureRandom().nextBytes(gcmKey);
        byte[] gcmResult = aesGcmEncrypt(gcmKey, msg, "aad".getBytes());
        System.out.printf("AES-256-GCM encrypted len=%d%n", gcmResult.length);

        // RSA-2048
        KeyPair rsa2048 = generateRsa2048();
        System.out.printf("RSA-2048 modulus bits=%d%n",
            ((RSAKey) rsa2048.getPublic()).getModulus().bitLength());

        // RSA-4096
        KeyPair rsa4096 = generateRsa4096();
        System.out.printf("RSA-4096 modulus bits=%d%n",
            ((RSAKey) rsa4096.getPublic()).getModulus().bitLength());

        // ECDSA P-256
        KeyPair ecKey = generateEcP256();
        byte[] ecSig = ecdsaSign(ecKey.getPrivate(), msg);
        System.out.printf("ECDSA P-256 signature len=%d%n", ecSig.length);

        // SHA-256 / SHA-512 / SHA-1 / MD5
        System.out.printf("SHA-256=%s%n", Base64.getEncoder().encodeToString(sha256(msg)));
        System.out.printf("SHA-512 len=%d%n", sha512(msg).length);
        System.out.printf("SHA-1 (legacy)=%s%n", Base64.getEncoder().encodeToString(sha1Legacy(msg)));
        System.out.printf("MD5   (legacy)=%s%n", Base64.getEncoder().encodeToString(md5Legacy(msg)));

        // HMAC-SHA256
        byte[] hmacKey = new byte[32];
        new SecureRandom().nextBytes(hmacKey);
        System.out.printf("HMAC-SHA256=%s%n",
            Base64.getEncoder().encodeToString(hmacSha256(hmacKey, msg)));

        // SSLContext TLS 1.2 / 1.3
        SSLContext tls12 = createTls12Context();
        System.out.printf("SSLContext TLS 1.2 protocol=%s%n", tls12.getProtocol());
        SSLContext tls13 = createTls13Context();
        System.out.printf("SSLContext TLS 1.3 protocol=%s%n", tls13.getProtocol());
    }
}
