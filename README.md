![CI](https://github.com/AaronErhardt/actix-governor/workflows/CI/badge.svg?branch=main)
[![Docs](https://docs.rs/actix-governor/badge.svg)](https://docs.rs/actix-governor/)
[![crates.io](https://img.shields.io/crates/v/actix-governor.svg)](https://crates.io/crates/actix-governor)

# Actix Governor

A middleware for [actix-web](https://github.com/actix/actix-web) that provides
rate-limiting backed by [governor](https://github.com/antifuchs/governor).

## Features:

- Simple to use
- High customizability
- High performance
- Robust yet flexible API

## Example

```rust
use actix_governor::{Governor, GovernorConfigBuilder};
use actix_web::{web, App, HttpServer, Responder};

async fn index() -> impl Responder {
    "Hello world!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Allow bursts with up to five requests per IP address
    // and replenishes two elements per second
    let governor_conf = GovernorConfigBuilder::default()
        .requests_per_second(2)
        .burst_size(5)
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
```

### Add this to your `Cargo.toml`:

```toml
[dependencies]
actix-governor = "0.6"
```
