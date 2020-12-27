//! An middleware for [actix-web](https://github.com/actix/actix-web) that provides
//! rate-limiting backed by [governor](https://github.com/antifuchs/governor).
//!
//! # Features:
//!
//! + Simple to use
//! + High performance
//! + Robust yet flexible API
//! + Actively maintained as part of the [Triox-Project](https://github.com/AaronErhardt/Triox)
//!
//! # How does it work?
//!
//! Each governor middleware has a configuration that stores a quota.
//! The quota specifies how many requests can be send from a IP address
//! before the middleware starts blocking further requests.
//!
//! For example if the quota allowed ten requests a client could send a burst of
//! ten requests in short time before the middleware starts blocking.
//!
//! Once at least one element of the quota was used the elements of the quota
//! will be replenished after a specified period.
//!
//! For example if this period was 2 seconds and the quota was empty
//! it would take 2 seconds to replenish one element of the quota.
//! This means you could send one request every two seconds on average.
//!
//! If there was a quota that allowed ten requests with the same period
//! the client could again send a burst of ten requests and then had to wait
//! two seconds before sending further requests or 20 seconds before the full
//! quota would be replenished an he could send another burst.
//!
//! # Example
//! ```rust,no_run
//! use actix_governor::{Governor, GovernorConfigBuilder};
//! use actix_web::{web, App, HttpServer, Responder};
//!
//! async fn index() -> impl Responder {
//!     "Hello world!"
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Allow bursts with up to five requests per IP address
//!     // and replenishes one element every two seconds
//!     let governor_conf = GovernorConfigBuilder::default()
//!         .per_second(2)
//!         .burst_size(5)
//!         .finish()
//!         .unwrap();
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             // Enable Governor middleware
//!             .wrap(Governor::new(&governor_conf))
//!             // Route hello world service
//!             .route("/", web::get().to(index))
//!    })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//! ```
//!
//! # Configuration presets
//!
//! Instead of using the configuration builder you can use predefined presets.
//!
//! + [`GovernorConfig::default()`]: The default configuration which is suitable for most services.
//! Allows bursts with up to eight requests and replenishes one element after 500ms.
//!
//! + [`GovernorConfig::secure()`]: A default configuration for security related services.
//! Allows bursts with up to two requests and replenishes one element after four seconds.
//!
//! For example the secure configuration can be used as a short version of this code:
//!
//! ```rust
//! let config = GovernorConfigBuilder::default()
//!      .per_second(4)
//!      .burst_size(2)
//!      .finish()
//!      .unwrap();
//! ```
//!
//! # Common pitfalls
//!
//! Do not construct the same configuration multiple times, unless explicitly wanted!
//! This will create an independent rate limiter for each configuration!
//!
//! Instead pass the same configuration reference into [`Governor::new()`],
//! like it is described in the example.

#[cfg(test)]
mod tests;

use governor::{
    clock::{Clock, DefaultClock},
    state::keyed::DefaultKeyedStateStore,
    Quota, RateLimiter,
};

use std::{
    cell::RefCell,
    net::IpAddr,
    num::NonZeroU32,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, error, Error};
use futures::future::{ok, Ready};
use futures::Future;

const DEFAULT_PERIOD: Duration = Duration::from_millis(500);
const DEFAULT_BURST_SIZE: u32 = 8;

/// Helper struct for building a configuration for the governor middleware
///
/// # Example
///
/// Create a configuration with a quota of ten requests per IP address
/// that replenishes one element every minute.
///
/// ```rust
/// use actix_governor::GovernorConfigBuilder;
///
/// let config = GovernorConfigBuilder::default()
///     .per_second(60)
///     .burst_size(10)
///     .finish()
///     .unwrap();
/// ```
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GovernorConfigBuilder {
    period: Duration,
    burst_size: u32,
}

impl Default for GovernorConfigBuilder {
    /// The default configuration which is suitable for most services.
    /// Allows burst with up to eight requests and replenishes one element after 500ms.
    /// The values can be modified by calling other methods on this struct.
    fn default() -> Self {
        GovernorConfigBuilder {
            period: DEFAULT_PERIOD,
            burst_size: DEFAULT_BURST_SIZE,
        }
    }
}

impl GovernorConfigBuilder {
    /// Set the interval after which one element of the quota is replenished.
    ///
    /// **The interval must not be zero.**
    pub fn period(&mut self, duration: Duration) -> &mut Self {
        self.period = duration;
        self
    }
    /// Set the interval after which one element of the quota is replenished in seconds.
    ///
    /// **The interval must not be zero.**
    pub fn per_second(&mut self, seconds: u64) -> &mut Self {
        self.period = Duration::from_secs(seconds);
        self
    }
    /// Set the interval after which one element of the quota is replenished in milliseconds.
    ///
    /// **The interval must not be zero.**
    pub fn per_millisecond(&mut self, milliseconds: u64) -> &mut Self {
        self.period = Duration::from_millis(milliseconds);
        self
    }
    /// Set the interval after which one element of the quota is replenished in nanoseconds.
    ///
    /// **The interval must not be zero.**
    pub fn per_nanosecond(&mut self, nanoseconds: u64) -> &mut Self {
        self.period = Duration::from_nanos(nanoseconds);
        self
    }
    /// Set quota size that defines how many requests can occur
    /// before the governor middleware starts blocking requests from an IP address and
    /// clients have to wait until the elements of the quota are replenished.
    ///
    /// **The burst_size must not be zero.**
    pub fn burst_size(&mut self, burst_size: u32) -> &mut Self {
        self.burst_size = burst_size;
        self
    }
    /// Finish building the configuration and return the configuration for the middleware.
    /// Returns `None` if either burst size or period interval are zero.
    pub fn finish(&mut self) -> Option<GovernorConfig> {
        if self.burst_size != 0 && self.period.as_nanos() != 0 {
            Some(GovernorConfig {
                limiter: Arc::new(RateLimiter::keyed(
                    Quota::with_period(self.period)
                        .unwrap()
                        .allow_burst(NonZeroU32::new(self.burst_size).unwrap()),
                )),
            })
        } else {
            None
        }
    }
}

#[derive(Clone)]
/// Configuration for the Governor middleware.
pub struct GovernorConfig {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl Default for GovernorConfig {
    /// The default configuration which is suitable for most services.
    /// Allows bursts with up to eight requests and replenishes one element after 500ms.
    fn default() -> Self {
        GovernorConfigBuilder {
            period: DEFAULT_PERIOD,
            burst_size: DEFAULT_BURST_SIZE,
        }
        .finish()
        .unwrap()
    }
}

impl GovernorConfig {
    /// A default configuration for security related services.
    /// Allows bursts with up to two requests and replenishes one element after four seconds.
    ///
    /// This prevents brute-forcing passwords or security tokens
    /// yet allows to quickly retype a wrong password once before the quota is exceeded.
    pub fn secure() -> Self {
        GovernorConfigBuilder {
            period: Duration::from_secs(4),
            burst_size: 2,
        }
        .finish()
        .unwrap()
    }
}

/// Governor middleware factory.
pub struct Governor {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl Governor {
    /// Create new governor middleware factory from configuration.
    pub fn new(config: &GovernorConfig) -> Governor {
        Governor {
            limiter: config.limiter.clone(),
        }
    }
}

impl<S, B> Transform<S> for Governor
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
    S: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = S::Error;
    type InitError = ();
    type Transform = GovernorMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(GovernorMiddleware::<S> {
            service: Rc::new(RefCell::new(service)),
            limiter: self.limiter.clone(),
        })
    }
}

pub struct GovernorMiddleware<S> {
    service: std::rc::Rc<std::cell::RefCell<S>>,
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl<S: 'static, B> Service for GovernorMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let ip = if let Some(addr) = req.peer_addr() {
            addr.ip()
        } else {
            return Box::pin(async {
                Err(error::ErrorInternalServerError(
                    "Couldn't find peer address",
                ))
            });
        };

        // clone to prevent moving values into the closure
        let mut srv = self.service.clone();
        let limiter = self.limiter.clone();

        Box::pin(async move {
            match limiter.check_key(&ip) {
                Ok(_) => {
                    let res = srv.call(req).await?;
                    Ok(res)
                }
                Err(negative) => {
                    let wait_time = negative
                        .wait_time_from(DefaultClock::default().now())
                        .as_secs();
                    log::info!(
                        "Rate limit exceeded for client-IP [{}], quota reset in {}s",
                        &ip,
                        &wait_time
                    );
                    let wait_time_str = wait_time.to_string();
                    let response = actix_web::HttpResponse::TooManyRequests()
                        .set_header(actix_web::http::header::RETRY_AFTER, wait_time_str.clone())
                        .body(format!("Too many requests, retry in {}s", wait_time_str));
                    Err(response.into())
                }
            }
        })
    }
}
