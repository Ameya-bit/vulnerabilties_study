# SQL Injection Defense in Rust Web Applications   
<br>

**Last Updated**: May 2025  
**Rust Version**: 1.86.0  

A reference implementation for preventing SQL injection (SQLi) in Rust web apps, combining compile-time safety, ORM best practices, and defense-in-depth strategies.

---
<br>

## Key Features  
<br> 

✅ **Parameterized Queries** (SQLx macros, Diesel ORM)  
✅ **Input Validation** (libinjection pattern matching)  
✅ **TLS Encryption** (Secure PostgreSQL connections)  
✅ **RBAC Templates** (Least-privilege database roles)  
✅ **Heuristic Monitoring** (UNION attack detection)  
✅ **Anti-Pattern Examples** (Safe vs unsafe code comparisons)  

---
<br>

## Installation  
<br>

```
[dependencies]
sqlx = { version = "0.7", features = ["postgres", "tracing"] }
diesel = { version = "2.1", features = ["postgres", "r2d2"] }
libinjection = "0.4"
tracing = "0.2"
```

---
<br>

## Usage  
<br>


### 1. Database Setup  

```
-- Configure least-privilege role
CREATE ROLE web_user WITH LOGIN PASSWORD 'secure';
GRANT SELECT, INSERT ON users TO web_user;
REVOKE DELETE, DROP ON ALL TABLES FROM web_user;
```
<br>

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
<br>

### 3. Input Validation  

```
validate_input(user_input)?; // Rejects ' OR 1=1--
```


---
<br>

## Security Deep Dive  
<br>

### Prevention Layers  
| Layer                | Implementation                          | Attack Mitigated          |
|----------------------|-----------------------------------------|---------------------------|
| **Parameterization** | SQLx `$1` placeholders, Diesel query DSL | Classic UNION-based SQLi  |
| **ORM Abstraction**  | Diesel `insert_into().values()`         | Query structure tampering |
| **Input Sanitization**| libinjection + custom regex            | Novel injection patterns  |
| **Transport Security**| TLS via `PgSslMode::Require`           | Network sniffing          |

---
<br>

## SQLx vs Diesel: Security Tradeoffs  
<br>

| Scenario              | SQLx Advantage                          | Diesel Advantage                 |
|-----------------------|-----------------------------------------|-----------------------------------|
| Complex Joins         | Manual SQL with macros                  | Type-safe query builder          |
| Async Requirements    | Native async/await                      | Sync-only                         |
| Schema Flexibility    | Handles DB drift                        | Compile-time schema matching      |
| Injection Protection  | Compile-time query checking             | Zero raw SQL exposure             |

---
<br>

## Anti-Patterns to Avoid  
<br>

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
<br>

## Monitoring & RBAC  
<br>

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
<br>

## References  
<br>

1. [OWASP SQL Injection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)  
2. [SQLx Runtime Safety Documentation](https://docs.rs/sqlx/latest/sqlx/)  
3. [Diesel Query Builder Best Practices](https://diesel.rs/guides/)  
4. [30 Vulnerabilities - SQL Injection](https://it4chis3c.medium.com/day-4-of-30-days-30-vulnerabilities-sql-injection-4c55730c14b4)


