# Secure Data Handling in Rust

A Rust library for preventing sensitive data exposure through memory-safe operations, modern cryptography, and secure secret management.

## Features

### Core Security Strategies
- **Memory Safety**: Automatic zeroization of secrets using Rust's ownership system
- **Password Security**: bcrypt hashing with salt and configurable work factor
- **Authenticated Encryption**: ChaCha20-Poly1305 for confidential+verified data
- **Secret Wrapping**: `SecretString` prevents accidental logging/exposure

## Installation

Add to `Cargo.toml`:

```
[dependencies]
secrecy = "0.10"
bcrypt = "0.13"
chacha20poly1305 = "0.10"
sha2 = "0.10"
hex = "0.4" # For test assertions
```


## API Reference

### Secret Management

```
/// Securely wraps strings, prevents debug logging, zeros memory on drop
/// Example: create_secret("api-key") → SecretString
pub fn create_secret(data: &str) -> SecretString
```


### Password Handling

```
/// bcrypt hash with DEFAULT_COST (12 rounds)
/// Example: hash_password("p@ssw0rd") → "$2b$12$..."
pub fn hash_password(password: &str) -> Result<String, BcryptError>

/// Constant-time bcrypt verification
/// Example: verify_password("guess", hash) → Ok(false)
pub fn verify_password(password: &str, hashed: &str) -> Result<bool, BcryptError>
```


### Cryptography

```
/// Encrypts data with ChaCha20-Poly1305 (requires 256-bit key, 96-bit nonce)
/// Example: encrypt_secret(key, nonce, b"secret") → Vec<u8>
pub fn encrypt_secret(key: &Key, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, AeadError>

/// Decrypts and verifies data integrity
/// Example: decrypt_secret(key, nonce, ciphertext) → Ok(b"secret")
pub fn decrypt_secret(key: &Key, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, AeadError>
```


## Usage Example

```
use secrecy::ExposeSecret;
use chacha20poly1305::{KeyInit, OsRng};

fn main() {
// Secret handling
let api_key = create_secret("sup3r-s3cr3t");
println!("Key: {}", api_key.expose_secret());

// Password workflow
let hash = hash_password("user-p@ss").unwrap();
assert!(verify_password("user-p@ss", &hash).unwrap());

// Encryption
let key = ChaCha20Poly1305::generate_key(&mut OsRng);
let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
let ciphertext = encrypt_secret(&key, &nonce, b"credit-card").unwrap();
let plaintext = decrypt_secret(&key, &nonce, &ciphertext).unwrap();

}
```


## Security Best Practices

1. **Secret Management**
   - Always use `SecretString` for sensitive data
   - Call `expose_secret()` only when absolutely necessary
   - Never log secrets directly

2. **Cryptography**
   - Generate keys with `ChaCha20Poly1305::generate_key()`
   - Never reuse (key, nonce) pairs
   - Rotate encryption keys regularly

3. **Memory Safety**
   - Avoid unnecessary copies of sensitive data
   - Use `Pin<T>` for secrets that shouldn't be moved
   - Enable `mlock()` in production via OS-specific config

## Testing

Run comprehensive security tests:

```
cargo test -- --test-threads=1
```


Tests verify:
- Memory zeroization
- Password hash verification
- Encryption/decryption roundtrips
- Tampered ciphertext rejection
- Constant-time comparison safety

## Contributing

1. Security audits must pass `cargo audit`
2. All cryptographic code requires fuzz testing
3. Document threat model for new features

## License

MIT License 

## References

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Rust Crypto Guidelines](https://rustcrypto.github.io/secrets/)
- [ChaCha20-Poly1305 RFC](https://tools.ietf.org/html/rfc8439)
- [30 Vulnerabilities - Sensitive Data Exposure](https://it4chis3c.medium.com/day-6-of-30-days-30-vulnerabilities-sensitive-data-exposure-8001f758ac61)

