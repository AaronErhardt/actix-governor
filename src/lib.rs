//! A middleware for [actionable](https://github.com/actix/actix-web) that provides
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
//! The quota specifies how many requests can be sent from an IP address
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
//! a client could again send a burst of ten requests and then had to wait
//! two seconds before sending further requests or 20 seconds before the full
//! quota would be replenished and he could send another burst.
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
//! use actix_governor::GovernorConfigBuilder;
//!
//! let config = GovernorConfigBuilder::default()
//!     .per_second(4)
//!     .burst_size(2)
//!     .finish()
//!     .unwrap();
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
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{body::MessageBody, error, Error};
use futures::future;

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
    methods: Option<Vec<Method>>,
}

impl Default for GovernorConfigBuilder {
    /// The default configuration which is suitable for most services.
    /// Allows burst with up to eight requests and replenishes one element after 500ms.
    /// The values can be modified by calling other methods on this struct.
    fn default() -> Self {
        GovernorConfigBuilder {
            period: DEFAULT_PERIOD,
            burst_size: DEFAULT_BURST_SIZE,
            methods: None,
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

    /// Set the HTTP methods this configuration should apply to.
    /// By default this is all methods
    pub fn methods(&mut self, methods: Vec<Method>) -> &mut Self {
        self.methods = Some(methods);
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
                methods: self.methods.clone(),
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
/// Configuration for the Governor middleware.
pub struct GovernorConfig {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    methods: Option<Vec<Method>>,
}

impl Default for GovernorConfig {
    /// The default configuration which is suitable for most services.
    /// Allows bursts with up to eight requests and replenishes one element after 500ms.
    fn default() -> Self {
        GovernorConfigBuilder {
            period: DEFAULT_PERIOD,
            burst_size: DEFAULT_BURST_SIZE,
            methods: None,
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
            methods: None,
        }
        .finish()
        .unwrap()
    }
}

/// Governor middleware factory.
pub struct Governor {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    methods: Option<Vec<Method>>,
}

impl Governor {
    /// Create new governor middleware factory from configuration.
    pub fn new(config: &GovernorConfig) -> Governor {
        Governor {
            limiter: config.limiter.clone(),
            methods: config.methods.clone(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Governor
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = GovernorMiddleware<S>;
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(GovernorMiddleware::<S> {
            service: Rc::new(RefCell::new(service)),
            limiter: self.limiter.clone(),
            methods: self.methods.clone(),
        })
    }
}

pub struct GovernorMiddleware<S> {
    service: std::rc::Rc<std::cell::RefCell<S>>,
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
    methods: Option<Vec<Method>>,
}

impl<S, B> Service<ServiceRequest> for GovernorMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future =
        future::Either<future::Ready<Result<ServiceResponse<B>, actix_web::Error>>, S::Future>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(configured_methods) = &self.methods {
            if !configured_methods.contains(req.method()) {
                // The request method is not configured, we're ignoring this one.
                let fut = self.service.call(req);
                return future::Either::Right(fut);
            }
        }

        let ip = if let Some(addr) = req.peer_addr() {
            addr.ip()
        } else {
            return future::Either::Left(future::err(error::ErrorInternalServerError(
                "Couldn't find peer address",
            )));
        };

        match self.limiter.check_key(&ip) {
            Ok(_) => {
                let fut = self.service.call(req);
                future::Either::Right(fut)
            }

            Err(negative) => {
                let wait_time = negative
                    .wait_time_from(DefaultClock::default().now())
                    .as_secs();
                #[cfg(feature = "log")]
                log::info!(
                    "Rate limit exceeded for client-IP [{}], quota reset in {}s",
                    &ip,
                    &wait_time
                );
                let wait_time_str = wait_time.to_string();
                let body = format!("Too many requests, retry in {}s", wait_time_str);
                let response = actix_web::HttpResponse::TooManyRequests()
                    .insert_header((actix_web::http::header::RETRY_AFTER, wait_time_str))
                    .body(&body);
                future::Either::Left(future::err(
                    error::InternalError::from_response(body, response).into(),
                ))
            }
        }
    }
}
