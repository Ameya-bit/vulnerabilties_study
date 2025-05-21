// src/secrets.rs

use secrecy::{ExposeSecret, SecretString};
use sha2::{Sha256, Digest};
use bcrypt::{hash, verify, DEFAULT_COST};
use chacha20poly1305::{
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng, Error as AeadError},
    ChaCha20Poly1305, Key, Nonce
};

/// Wraps a sensitive string in a secure container.
/// Prevents accidental leaks (e.g., via logs) and ensures memory is wiped on drop.
/// Use this for API keys, tokens, or any secrets handled in memory.
pub fn create_secret(data: &str) -> SecretString {
    SecretString::new(data.to_owned().into())
}

/// Computes the SHA-256 hash of input data.
/// Useful for data integrity checks, fingerprinting, or storing non-reversible identifiers.
/// Do not use for password storage—use bcrypt for that.
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    Sha256::digest(data).to_vec()
}

/// Hashes a password using bcrypt, which includes a random salt and work factor.
/// Protects user passwords against brute-force and rainbow table attacks.
/// Store only the resulting hash, never the plaintext password.
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

/// Verifies a plaintext password against a bcrypt hash using constant-time comparison.
/// Prevents timing attacks and ensures only valid credentials are accepted.
/// Returns Ok(true) if the password matches, Ok(false) if not, or an error if the hash is invalid.
pub fn verify_password(password: &str, hashed: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hashed)
}

/// Encrypts data using the ChaCha20-Poly1305 AEAD cipher for confidentiality and authenticity.
/// Requires a unique key and nonce for each encryption to prevent replay and nonce reuse attacks.
/// Returns ciphertext that includes an authentication tag to detect tampering.
pub fn encrypt_secret(
    key: &Key,
    nonce: &Nonce,
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = plaintext.to_vec();
    cipher.encrypt_in_place(nonce, b"", &mut buffer)?;
    Ok(buffer)
}

/// Decrypts data encrypted by `encrypt_secret`, verifying its authenticity.
/// If the ciphertext or authentication tag is tampered, decryption fails.
/// Returns the original plaintext if successful, or an error if verification fails.
pub fn decrypt_secret(
    key: &Key,
    nonce: &Nonce,
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let cipher = ChaCha20Poly1305::new(key);
    let mut buffer = ciphertext.to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::OsRng;

    #[test]
    fn test_secret_handling() {
        // Ensures secrets are wrapped and exposed correctly.
        let secret = create_secret("confidential");
        assert_eq!(secret.expose_secret(), "confidential");
    }

    #[test]
    fn test_encryption_and_decryption() {
        // Checks round-trip encryption and decryption for data integrity.
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let plaintext = b"supersecret";
        let ciphertext = encrypt_secret(&key, &nonce, plaintext).unwrap();
        let decrypted = decrypt_secret(&key, &nonce, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_password_workflow() {
        // Verifies password hashing and authentication logic.
        let password = "Str0ngP@ssw0rd!";
        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_sha256_known_value() {
        // Confirms SHA-256 hashing produces expected output.
        let data = b"hello world";
        let hash = hash_data(data);
        assert_eq!(
            hex::encode(hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_tampered_ciphertext() {
        // Ensures tampered ciphertext fails authentication.
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut ciphertext = encrypt_secret(&key, &nonce, b"valid").unwrap();
        ciphertext[0] ^= 0x01;
        assert!(decrypt_secret(&key, &nonce, &ciphertext).is_err());
    }
}

fn main() {
    // Example: securely wrap and print a secret.
    let secret = create_secret("my_top_secret");
    println!("Protected secret: {}", secret.expose_secret());

    // Example: hash and verify a password.
    let password = "UserPassword123!";
    let hash = hash_password(password).unwrap();
    println!("Password verified: {}", verify_password(password, &hash).unwrap());

    // Example: encrypt and decrypt data.
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let plaintext = b"Sensitive corporate data";
    let ciphertext = encrypt_secret(&key, &nonce, plaintext).unwrap();
    let decrypted = decrypt_secret(&key, &nonce, &ciphertext).unwrap();
    println!("Decrypted: {}", String::from_utf8_lossy(&decrypted));
}
