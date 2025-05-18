# SQL Injection Defense in Rust Web Applications  
**Last Updated**: May 2025  
**Rust Version**: 1.86.0  

A reference implementation for preventing SQL injection (SQLi) in Rust web apps, combining compile-time safety, ORM best practices, and defense-in-depth strategies.

---

## Key Features  
✅ **Parameterized Queries** (SQLx macros, Diesel ORM)  
✅ **Input Validation** (libinjection pattern matching)  
✅ **TLS Encryption** (Secure PostgreSQL connections)  
✅ **RBAC Templates** (Least-privilege database roles)  
✅ **Heuristic Monitoring** (UNION attack detection)  
✅ **Anti-Pattern Examples** (Safe vs unsafe code comparisons)  

---

## Installation  
```
[dependencies]
sqlx = { version = "0.7", features = ["postgres", "tracing"] }
diesel = { version = "2.1", features = ["postgres", "r2d2"] }
libinjection = "0.4"
tracing = "0.2"
```

---

## Usage  

### 1. Database Setup  

```
-- Configure least-privilege role
CREATE ROLE web_user WITH LOGIN PASSWORD 'secure';
GRANT SELECT, INSERT ON users TO web_user;
REVOKE DELETE, DROP ON ALL TABLES FROM web_user;
```

### 2. Secure User Creation  
**SQLx (Async):**

```
let pool = create_sqlx_pool("postgres://web_user:secure@localhost/db").await?;
create_user_sqlx(&pool, "alice", "alice@example.com").await?;
```


**Diesel (Sync):**

```
let mut conn = create_diesel_conn("postgres://web_user:secure@localhost/db")?;
create_user_diesel(&mut conn, "bob", "bob@example.com")?;
```


### 3. Input Validation  

```
validate_input(user_input)?; // Rejects ' OR 1=1--
```


---

## Security Deep Dive  

### Prevention Layers  
| Layer                | Implementation                          | Attack Mitigated          |
|----------------------|-----------------------------------------|---------------------------|
| **Parameterization** | SQLx `$1` placeholders, Diesel query DSL | Classic UNION-based SQLi  |
| **ORM Abstraction**  | Diesel `insert_into().values()`         | Query structure tampering |
| **Input Sanitization**| libinjection + custom regex            | Novel injection patterns  |
| **Transport Security**| TLS via `PgSslMode::Require`           | Network sniffing          |

---

## SQLx vs Diesel: Security Tradeoffs  

| Scenario              | SQLx Advantage                          | Diesel Advantage                 |
|-----------------------|-----------------------------------------|-----------------------------------|
| Complex Joins         | Manual SQL with macros                  | Type-safe query builder          |
| Async Requirements    | Native async/await                      | Sync-only                         |
| Schema Flexibility    | Handles DB drift                        | Compile-time schema matching      |
| Injection Protection  | Compile-time query checking             | Zero raw SQL exposure             |

---

## Anti-Patterns to Avoid  

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

## Monitoring & RBAC  

### Query Analysis  

```
analyze_query("SELECT * FROM users UNION SELECT * FROM passwords");
// Logs: "Potential UNION attack detected"
```


### Role-Based Access Control  

```
-- Template for production databases
GRANT SELECT, INSERT ON public TO web_user;
REVOKE EXECUTE ON PROCEDURE create_user FROM web_user;
```


---

## References  
1. [OWASP SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)  
2. [SQLx Runtime Safety Documentation](https://docs.rs/sqlx/latest/sqlx/)  
3. [Diesel Query Builder Best Practices](https://diesel.rs/guides/)  
4. [30 Vulnerabilities - SQL Injection](https://it4chis3c.medium.com/day-4-of-30-days-30-vulnerabilities-sql-injection-4c55730c14b4)


