# SQL Injection Defense in Rust Web Applications  
**Last Updated**: May 2025  
**Rust Version**: 1.86.0  

A reference implementation for preventing SQL injection (SQLi) in Rust web apps, combining compile-time safety, ORM best practices, and defense-in-depth strategies.

---

## Key Features  
- **Parameterized Queries** (SQLx macros, Diesel ORM)  
- **Input Validation** (Regex-based SQLi pattern matching)  
- **TLS Encryption** (Secure PostgreSQL connections, optional)  
- **RBAC Templates** (Least-privilege database roles)  
- **Heuristic Monitoring** (UNION attack detection)  
- **Anti-Pattern Examples** (Safe vs unsafe code comparisons)  

---

## Installation  
Add to your `Cargo.toml`:

```
[dependencies]
sqlx = { version = "0.8.1", features = ["postgres", "runtime-tokio-native-tls"] }
diesel = { version = "2.1", features = ["postgres", "r2d2"] }
regex = "1.10.3"
tracing = "0.2"
dotenvy = "0.15"
```


---

## Usage  

### 1. Database Setup  

Connect as a superuser and run:

```
-- Configure least-privilege role
CREATE ROLE web_user WITH LOGIN PASSWORD 'secure';
GRANT SELECT, INSERT ON users TO web_user;
REVOKE DELETE, DROP ON ALL TABLES FROM web_user;\
```


### 2. Running the Example

1. **Set your `.env` file** (in the project root):


```
DATABASE_URL=postgres://postgres:your_password@localhost:5432/postgres
```

(This must be a superuser for test database creation.)

2. **Build and run:**


```
cargo run
```


This will:
- Create a test database (`sqlidemo_test`)
- Set up the schema and stored procedure
- Run a series of SQLi and safe input tests with both SQLx and Diesel
- Print results to the console

---

### 3. Secure User Creation  
**SQLx (Async):**

```
let pool = create_sqlx_pool("postgres://web_user:secure@localhost/sqlidemo_test").await?;
create_user_sqlx(&pool, "alice", "alice@example.com").await?;
```


**Diesel (Sync):**

```


```
let mut conn = create_diesel_conn("postgres://web_user:secure@localhost/sqlidemo_test")?;
create_user_diesel(&mut conn, "bob", "bob@example.com")?;
```


---

### 4. Input Validation  


```
validate_input(user_input)?; // Rejects ' OR 1=1--
```

- Uses a regex pattern to block common SQLi signatures and dangerous input.

---

### 5. Security Deep Dive  

#### Prevention Layers  
| Layer                | Implementation                          | Attack Mitigated          |
|----------------------|-----------------------------------------|---------------------------|
| **Parameterization** | SQLx `$1` placeholders, Diesel query DSL | Classic SQLi, UNION-based |
| **ORM Abstraction**  | Diesel `insert_into().values()`         | Query structure tampering |
| **Input Sanitization**| Regex-based filtering                  | Novel injection patterns  |
| **Transport Security**| TLS via `PgSslMode` (optional)         | Network sniffing          |

---

### 6. SQLx vs Diesel: Security Tradeoffs  

| Scenario              | SQLx Advantage                          | Diesel Advantage                 |
|-----------------------|-----------------------------------------|-----------------------------------|
| Complex Joins         | Manual SQL with macros                  | Type-safe query builder          |
| Async Requirements    | Native async/await                      | Sync-only                        |
| Schema Flexibility    | Handles DB drift                        | Compile-time schema matching     |
| Injection Protection  | Compile-time query checking             | Zero raw SQL exposure            |

---

### 7. Anti-Patterns to Avoid  

❌ **Raw SQL Concatenation**  

```
// UNSAFE: Input directly embedded in SQL
diesel::sql_query(format!("SELECT * FROM users WHERE name = '{}'", input));
```


✅ **Safe Alternative**  


```
// Parameterized via query builder
users.filter(name.eq(input)).first::<User>(conn)?;
```


---

### 8. Monitoring & RBAC  

#### Query Analysis  

```
analyze_query("SELECT * FROM users UNION SELECT * FROM passwords");
// Logs: "Potential UNION attack detected"
```


#### Role-Based Access Control  


```
-- Template for production databases
GRANT SELECT, INSERT ON users TO web_user;
REVOKE DELETE, DROP ON ALL TABLES FROM web_user;
```


---

### 9. Example Output


```
=== Testing SQLx User Creation ===
Attempting to create user: safe_user safe@example.com
✅ User created: SqlxUser { id: Some(1), username: Some("safe_user"), email: Some("safe@example.com") }
Attempting to create user: ' OR 1=1;-- malicious@example.com
❌ Failed: Potential SQL injection detected
Attempting to create user: UNION SELECT * FROM users union_attack@example.com
❌ Failed: Potential SQL injection detected
Attempting to create user: ; DROP TABLE users drop_attack@example.com
❌ Failed: Potential SQL injection detected

=== Testing Diesel ORM ===
Attempting Diesel ORM: safe_user safe@example.com
✅ User created: DieselUser { id: 1, username: "safe_user", email: "safe@example.com" }
Attempting Diesel ORM: ' OR 1=1;-- malicious@example.com
❌ Failed: Potential SQL injection detected
...

=== Testing Query Monitoring ===
Potential UNION attack: SELECT * FROM users WHERE id=1; UNION SELECT * FROM secrets
```


---

## References  
1. [OWASP SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)  
2. [SQLx Runtime Safety Documentation](https://docs.rs/sqlx/latest/sqlx/)  
3. [Diesel Query Builder Best Practices](https://diesel.rs/guides/)  
4. [StackHawk: Rust SQL Injection Guide](https://www.stackhawk.com/blog/rust-sql-injection-guide-examples-and-prevention/)  
5. [Reddit: How to avoid SQL injection attacks in Rust?](https://www.reddit.com/r/rust/comments/193bnm0/how_to_avoid_sql_injection_attacks_in_rust/)  
6. [Kiuwan: Top 5 Best Practices for Preventing SQL Injection Attacks](https://www.kiuwan.com/blog/top-5-best-practices-for-developers-on-preventing-sql-injections-attacks/)  
7. [30 Vulnerabilites - SQL injection](https://it4chis3c.medium.com/day-4-of-30-days-30-vulnerabilities-sql-injection-4c55730c14b4)

---


