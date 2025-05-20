# Rust Open Redirect Demo

This project demonstrates secure handling of redirects in a Rust web application using [Actix-Web](https://actix.rs/) and the [`url`](https://docs.rs/url) crate. It implements best practices to prevent open redirect vulnerabilities, including allow-list validation, token-based redirects, and robust middleware.

---

## Features

- **Allow-list based redirect validation**
- **Token-based safe redirects**
- **Middleware to intercept and validate redirect parameters**
- **Comprehensive error handling**
- **HTTP access logging using env_logger**

---

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (edition 2021, Rust 1.72+ recommended)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

### Dependencies

Add these to your `Cargo.toml`:

```
[dependencies]
actix-web = "4"
url = "2"
env_logger = "0.11"
log = "0.4"
```


---

## Running the Project

1. **Clone the repository**

```
git clone https://github.com/Ameya-bit/vulnerabilties_study
cd rust-open-redirect-demo
```


2. **Build and run the server with logging enabled**

```
On Linux/macOS
RUST_LOG=info cargo run

On Windows PowerShell
$env:RUST_LOG="info"; cargo run
```


3. **Test endpoints using curl or your browser**

---

## API Endpoints

| Endpoint                                                | Method | Description                                      | Example Test                                                      |
|---------------------------------------------------------|--------|--------------------------------------------------|-------------------------------------------------------------------|
| `/safe_redirect/{token}`                                | GET    | Redirects to a safe, allow-listed URL            | `curl -v http://127.0.0.1:8080/safe_redirect/dashboard`           |
| `/login?redirect=https://trusted.com/profile`           | GET    | Redirects if URL is in allow-list                | `curl -v "http://127.0.0.1:8080/login?redirect=https://trusted.com/profile"` |
| `/login?redirect=https://evil.com`                      | GET    | Returns 403 for untrusted domain                 | `curl -v "http://127.0.0.1:8080/login?redirect=https://evil.com"` |
| `/login`                                                | GET    | Returns 400 for missing redirect parameter       | `curl -v "http://127.0.0.1:8080/login"`                           |

---

## Example Usage

```
Valid token-based redirect (should return 302 Found)
curl -v http://127.0.0.1:8080/safe_redirect/dashboard

Invalid token (should return 404 Not Found)
curl -v http://127.0.0.1:8080/safe_redirect/unknown

Valid allow-listed redirect (should return 302 Found)
curl -v "http://127.0.0.1:8080/login?redirect=https://trusted.com/profile"

Disallowed redirect (should return 403 Forbidden)
curl -v "http://127.0.0.1:8080/login?redirect=https://evil.com"

Missing redirect parameter (should return 400 Bad Request)
curl -v "http://127.0.0.1:8080/login"
```


---

## Security Best Practices Demonstrated

- **Strict allow-list checking** for all user-supplied redirect URLs
- **Tokenized redirects** to eliminate user-controlled URLs
- **Middleware validation** to intercept and block unsafe redirects
- **Comprehensive logging** for audit and debugging

---

## License

MIT

---

## References

- [OWASP: Unvalidated Redirects and Forwards](https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
- [Actix-Web Documentation](https://docs.rs/actix-web)
- [Rust URL Crate](https://docs.rs/url)
- [30 Vulnerabilities - Open Redirects](https://it4chis3c.medium.com/day-5-of-30-days-30-vulnerabilities-open-redirects-8b6ba34cce70)