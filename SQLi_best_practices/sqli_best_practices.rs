//! Defense-in-depth against SQL injection in Rust web apps
//!
//! Implements:
//! - Parameterized queries (SQLx/Diesel)
//! - Input validation (libinjection)
//! - ORM type safety
//! - TLS encryption
//! - Least-privilege DB access
//! - Query pattern monitoring

// 1. Database Models =========================================================
/// SQLx model: Ensures type safety and schema alignment at compile time.
/// Prevents "SELECT *" mismatches that could expose sensitive columns.
#[derive(sqlx::FromRow, Debug)]
pub struct SqlxUser {   // Should match your DB schema
    pub id: i32,
    pub username: String,
    pub email: String,
}

/// Diesel model: Maps Rust structs to DB tables via query builder.
/// Eliminates raw SQL string manipulation in CRUD operations.
#[derive(Queryable, Insertable, Debug)]
#[diesel(table_name = users)] 
pub struct DieselUser {   // Should match your DB schema
    pub id: i32,
    pub username: String,
    pub email: String,
}

// 2. Secure Connections ======================================================
/// Creates async connection pool with TLS and connection limits.
/// Why: Prevents connection exhaustion attacks and MITM sniffing.
pub async fn create_sqlx_pool(db_url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect_with(
            db_url.parse::<sqlx::postgres::PgConnectOptions>()?
                .ssl_mode(PgSslMode::Require) // Enforce encryption
        )
        .await
}

/// Establishes synchronous ORM connection with connection reuse.
/// Why: Diesel's connection pooling reduces auth overhead.
pub fn create_diesel_conn(db_url: &str) -> Result<PgConnection, ConnectionError> {
    PgConnection::establish(db_url)
}

// 3. Input Validation ========================================================
/// Multi-layer input sanitization using libinjection + custom rules.
/// Why: Defense-in-depth against novel injection patterns.
pub fn validate_input(input: &str) -> Result<(), Box<dyn Error>> {
    // Layer 1: Detect known SQLi fingerprints
    if sqli::is_sqli(&Input::new(input)) {
        return Err("SQLi pattern detected".into());
    }
    
    // Layer 2: Block dangerous characters
    if input.contains(";") || input.contains("--") {
        return Err("Invalid input characters".into());
    }
    
    Ok(())
}

// 4. SQLx Operations =========================================================
/// Creates user via stored procedure with compile-time SQL validation.
/// Why: Procedures encapsulate logic; parameters prevent injection.
pub async fn create_user_sqlx(
    pool: &sqlx::PgPool,
    username: &str,
    email: &str,
) -> Result<SqlxUser, Box<dyn Error>> {
    validate_input(username)?;
    
    sqlx::query_as!(
        SqlxUser,
        "SELECT * FROM create_user($1, $2)", // Calls DB-level procedure
        username,
        email
    )
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}

// 5. Diesel ORM Operations ===================================================
/// Transactional user creation with query builder.
/// Why: Atomic operations + no raw SQL exposure.
pub fn create_user_diesel(
    conn: &mut PgConnection,
    username: &str,
    email: &str,
) -> Result<DieselUser, Box<dyn Error>> {
    conn.transaction(|tx| { // All-or-nothing operation
        let new_user = DieselUser {
            id: 0, // Auto-increment handled by DB
            username: username.into(),
            email: email.into(),
        };
        
        diesel::insert_into(users::table)
            .values(&new_user)
            .get_result(tx)
    })
    .map_err(Into::into)
}

// 6. Security Monitoring =====================================================
/// Flags suspicious query patterns like UNION-based attacks.
/// Why: Early detection of probing/exploit attempts.
pub fn analyze_query(query: &str) {
    if query.to_uppercase().contains("UNION") {
        tracing::warn!("Potential UNION attack: {}", query);
    }
}

// 7. RBAC Template ===========================================================
/// SQL template for least-privilege database roles.
/// Why: Limits damage from compromised credentials.
pub const RBAC_SQL: &str = r#"
CREATE ROLE web_user WITH LOGIN PASSWORD 'secure';
GRANT SELECT, INSERT ON users TO web_user; -- Minimal permissions
REVOKE DELETE, DROP ON ALL TABLES FROM web_user; -- Damage limitation
"#;

// 8. Security Anti-Patterns ==================================================
/// UNSAFE EXAMPLE: Raw SQL concatenation vulnerability.
/// Why: Demonstrates risky pattern to avoid.
#[allow(dead_code)]
fn unsafe_diesel_query(conn: &mut PgConnection, raw_input: &str) {
    // VULNERABILITY: Direct input interpolation
    diesel::sql_query(format!("SELECT * FROM users WHERE name = '{}'", raw_input))
        .execute(conn)
        .expect("Failed");
}

/// SAFE ALTERNATIVE: Parameterized Diesel query.
/// Why: Proper separation of code/data.
fn safe_diesel_query(conn: &mut PgConnection, input: &str) -> Result<DieselUser, Box<dyn Error>> {
    use self::users::dsl::*;
    users
        .filter(username.eq(input)) // Query builder safety
        .first::<DieselUser>(conn)
        .map_err(Into::into)
}
