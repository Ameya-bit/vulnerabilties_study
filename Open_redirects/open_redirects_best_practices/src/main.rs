// Import necessary Actix-Web components and other dependencies
use actix_web::{
    dev::{ServiceRequest, ServiceResponse}, 
    get, web, App, Error, HttpResponse, HttpServer,
    Responder, HttpRequest, 
    body::{MessageBody, BoxBody},
    middleware::{from_fn, Next, Logger}
};
use url::Url;

// List of trusted domains allowed for redirects (allow-list approach)
const ALLOWED_DOMAINS: [&str; 3] = ["trusted.com", "api.trusted.com", "docs.trusted.com"];

/// Validates user-provided redirect URLs against security best practices
/// Returns parsed Url if valid, or RedirectError if any checks fail
fn validate_redirect_url(input: &str) -> Result<Url, RedirectError> {
    // Parse input string into Url object
    let parsed_url = Url::parse(input)
        .map_err(|_| RedirectError::InvalidUrl)?;

    // Normalize path segments to prevent path traversal attacks
    // This ensures URLs with encoded characters (e.g., %2F) are properly handled
    parsed_url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .ok_or(RedirectError::InvalidPath)?;

    // Security checks:
    // 1. Enforce HTTPS to prevent downgrade attacks
    // 2. Verify host is in our allow-list
    if parsed_url.scheme() != "https" || !ALLOWED_DOMAINS.contains(&parsed_url.host_str().unwrap_or("")) {
        return Err(RedirectError::UntrustedDomain);
    }

    Ok(parsed_url)
}

/// Middleware that intercepts requests with redirect parameters
/// Validates all URLs passed in 'redirect' query parameters
async fn redirect_guard(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,  
) -> Result<ServiceResponse<BoxBody>, Error> {
    // Check if request contains a redirect parameter
    if let Some(redirect_param) = req.query_string().split('&').find(|s| s.starts_with("redirect=")) {
        let url = redirect_param.split_once('=').unwrap().1;
        
        match validate_redirect_url(url) {
            Ok(_) => {
                // Valid URL - proceed with request
                next.call(req).await.map(|res| res.map_into_boxed_body())
            }
            Err(e) => {
                // Block request with 403 Forbidden and error message
                let response = HttpResponse::Forbidden()
                    .body(format!("Invalid redirect: {}", e))
                    .map_into_boxed_body();
                Ok(req.into_response(response))
            }
        }
    } else {
        // No redirect parameter - proceed normally
        next.call(req).await.map(|res| res.map_into_boxed_body())
    }
}

/// Token-based redirect endpoint (OWASP recommended pattern)
/// Uses predefined tokens instead of user-supplied URLs
#[get("/safe_redirect/{token}")]
async fn token_redirect(
    token: web::Path<String>,
    redirect_map: web::Data<std::sync::Mutex<std::collections::HashMap<&'static str, &'static str>>>,
) -> impl Responder {
    // Lock the shared HashMap containing valid token-URL mappings
    let map = redirect_map.lock().unwrap();
    match map.get(token.as_str()) {
        Some(url) => HttpResponse::Found()
            .append_header(("Location", *url))
            .finish(),
        None => HttpResponse::NotFound().body("Invalid redirect token"),
    }
}

/// Custom error types for redirect validation failures
#[derive(Debug)]
enum RedirectError {
    InvalidUrl,      // Malformed URL structure
    InvalidPath,     // Contains dangerous path components
    UntrustedDomain, // Domain not in allow-list
}

// Implement Display for clean error messaging
impl std::fmt::Display for RedirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::InvalidUrl => write!(f, "Malformed URL structure"),
            Self::InvalidPath => write!(f, "Invalid path components"),
            Self::UntrustedDomain => write!(f, "Domain not in allow-list"),
        }
    }
}

/// Main entry point configuring and starting the web server
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger for request tracking
    env_logger::init();

    // Create thread-safe storage for token-URL mappings
    let redirect_map = web::Data::new(std::sync::Mutex::new(
        std::collections::HashMap::from([
            ("dashboard", "https://trusted.com/dash"),
            ("profile", "https://trusted.com/me"),
        ]),
    ));

    // Configure and start HTTP server
    HttpServer::new(move || {
        App::new()
            // Enable request logging middleware
            .wrap(Logger::default())
            // Share redirect map with all handlers
            .app_data(redirect_map.clone())
            // Add our security middleware
            .wrap(from_fn(redirect_guard))
            // Register token-based redirect handler
            .service(token_redirect)
            // Login endpoint with manual redirect validation
            .service(
                web::resource("/login")
                    .route(web::get().to(|req: HttpRequest| async move {
                        match req.query_string().split_once("redirect=") {
                            Some((_, url)) => match validate_redirect_url(url) {
                                Ok(valid_url) => HttpResponse::Found()
                                    .append_header(("Location", valid_url.to_string()))
                                    .finish(),
                                Err(e) => HttpResponse::Forbidden()
                                    .body(format!("Invalid redirect: {}", e))
                            },
                            None => HttpResponse::BadRequest().body("Missing redirect parameter")
                        }
                    }))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
