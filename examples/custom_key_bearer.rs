use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor};
use actix_web::dev::ServiceRequest;
use actix_web::{web, App, HttpServer, Responder};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
struct UserToken;

impl KeyExtractor for UserToken {
    type Key = String;
    type KeyExtractionError = &'static str;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "Bearer token"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        req.headers()
            .get("Authorization")
            .and_then(|token| token.to_str().ok())
            .and_then(|token| token.strip_prefix("Bearer "))
            .and_then(|token| Some(token.trim().to_owned()))
            .ok_or("You don't have permission to access")
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some("String".to_owned())
    }
}

async fn index() -> impl Responder {
    "Hello world!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Allow bursts with up to five requests per IP address
    // and replenishes one element every two seconds
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(20)
        .burst_size(5)
        .key_extractor(UserToken)
        .use_headers()
        .finish()
        .unwrap();

    HttpServer::new(move || {
        App::new()
            // Enable Governor middleware
            .wrap(Governor::new(&governor_conf))
            // Route hello world service
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
