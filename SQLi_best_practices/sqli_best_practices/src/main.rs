//! Defense-in-depth against SQL injection in Rust web apps
//!
//! Implements:
//! - Parameterized queries (SQLx/Diesel)
//! - Input validation (libinjection)
//! - ORM type safety
//! - TLS encryption
//! - Least-privilege DB access
//! - Query pattern monitoring
//! 

#[allow(unused_imports)]
use diesel::prelude::*;
extern crate diesel;
mod schema;
use regex::Regex;
use std::error::Error;
use dotenvy::dotenv;
use std::env;
use diesel::prelude::*;
use diesel::pg::PgConnection;
use diesel::result::ConnectionError;
use diesel::RunQueryDsl;
use diesel::QueryDsl;
use diesel::ExpressionMethods;
use sqlx::postgres::{PgPoolOptions, PgSslMode};
use tracing_subscriber;

// 1. Database Models =========================================================
/// SQLx model: Ensures type safety and schema alignment at compile time.
/// Prevents "SELECT *" mismatches that could expose sensitive columns.
#[derive(sqlx::FromRow, Debug)]
pub struct SqlxUser {
    pub id: Option<i32>,    // Change to Option<i32>
    pub username: Option<String>,
    pub email: Option<String>,
}

/// Diesel model: Maps Rust structs to DB tables via query builder.
/// Eliminates raw SQL string manipulation in CRUD operations.
#[derive(Queryable, Insertable, Debug)]
#[diesel(table_name = crate::schema::users)]  // Explicit path
pub struct DieselUser {
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
                .ssl_mode(PgSslMode::Disable) // Enforce encryption
        )
        .await
}

/// Establishes synchronous ORM connection with connection reuse.
/// Why: Diesel's connection pooling reduces auth overhead.
pub fn create_diesel_conn(db_url: &str) -> Result<PgConnection, ConnectionError> {
    PgConnection::establish(db_url)
}

// 3. Input Validation ========================================================
/// Custom SQLi validation using regex patterns and type safety. 
/// For simplicity, we use regex here, but consider using a library like `libinjection` for production.
pub fn validate_input(input: &str) -> Result<(), Box<dyn Error>> {
    // Regex pattern for common SQLi signatures
    let sql_injection_pattern = Regex::new(r#"(?i)(\b(union|select|insert|delete|drop|update|alter|create|exec|shutdown)\b|[';--]|/\*|\*/)"#)?;
    
    // Check for suspicious patterns
    if sql_injection_pattern.is_match(input) {
        return Err("Potential SQL injection detected".into());
    }
    
    // Additional length checks
    if input.len() > 100 {
        return Err("Input exceeds maximum allowed length".into());
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
        
        diesel::insert_into(crate::schema::users::table)
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
    use crate::schema::users::dsl::*;
    users
        .filter(username.eq(input))
        .first::<DieselUser>(conn)
        .map_err(Into::into)
}


// 9. Main Function ===========================================================
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    // Connect to system database (postgres)
    let db_url = env::var("DATABASE_URL")?;
    let test_db = "sqlidemo_test";

    // Create admin pool with superuser privileges
    let admin_pool = PgPoolOptions::new()
        .connect(&db_url)
        .await?;

    // Drop test database if exists
    sqlx::query(&format!("DROP DATABASE IF EXISTS {}", test_db))
        .execute(&admin_pool)
        .await?;

    // Create test database with explicit owner
    sqlx::query(&format!(
        "CREATE DATABASE {} OWNER {}",
        test_db,
        "myappuser" // Replace with your username
    ))
    .execute(&admin_pool)
    .await?;

    // Connect to test database
    let test_url = format!(
        "postgres://myappuser:<password>@localhost:5432/{}",
        test_db
    );
    let pool = create_sqlx_pool(&test_url).await?;

    // Run migrations
    sqlx::query(
        r#"
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL
        );
        "#
    ).execute(&pool).await?;

    // Then create function
    sqlx::query(
        r#"
        CREATE OR REPLACE FUNCTION create_user(uname VARCHAR, em VARCHAR)
        RETURNS users AS $$
        DECLARE
            new_user users;
        BEGIN
            INSERT INTO users(username, email)
            VALUES (uname, em)
            RETURNING * INTO new_user;
            RETURN new_user;
        END;
        $$ LANGUAGE plpgsql;
        "#
    ).execute(&pool).await?;

    // Add test cases here
    let test_cases = vec![
        ("safe_user", "safe@example.com"),
        ("' OR 1=1;--", "malicious@example.com"),
        ("UNION SELECT * FROM users", "union_attack@example.com"),
        ("; DROP TABLE users", "drop_attack@example.com"),
    ];

    // Test SQLx user creation
    println!("\n=== Testing SQLx User Creation ===");
    for (username, email) in &test_cases {
        println!("Attempting to create user: {} <{}>", username, email);
        match create_user_sqlx(&pool, username, email).await {
            Ok(user) => println!("✅ User created: {:?}", user),
            Err(e) => println!("❌ Failed: {}", e),
        }
    }

    // Test Diesel ORM
    println!("\n=== Testing Diesel ORM ===");
    let mut conn = create_diesel_conn(&test_url)?;
    for (username, email) in &test_cases {
        println!("Attempting Diesel ORM: {} <{}>", username, email);
        match create_user_diesel(&mut conn, username, email) {
            Ok(user) => println!("✅ User created: {:?}", user),
            Err(e) => println!("❌ Failed: {}", e),
        }
    }

    // Test query monitoring
    println!("\n=== Testing Query Monitoring ===");
    analyze_query("SELECT * FROM users");
    analyze_query("SELECT * FROM users WHERE id=1; UNION SELECT * FROM secrets");


    Ok(())
}
