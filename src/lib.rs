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
//! Allows bursts with up to eight requests and replenishes one element after 500ms, based on peer IP.
//!
//! + [`GovernorConfig::secure()`]: A default configuration for security related services.
//! Allows bursts with up to two requests and replenishes one element after four seconds, based on peer IP.
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
//! # Customize rate limiting key
//!
//! By default, rate limiting is done using the peer IP address (i.e. the IP address of the HTTP client that requested your app: either your user or a reverse proxy, depending on your deployment setup).
//! You can configure a different behavior which:
//! 1. can be useful in itself
//! 2. allows you to setup multiple instances of this middleware based on different keys (for example, if you want to apply rate limiting with different rates on IP and API keys at the same time)
//!
//! This is achieved by defining a [KeyExtractor] and giving it to a [Governor] instance.
//! Two ready-to-use key extractors are provided:
//! - [PeerIpKeyExtractor]: this is the default
//! - [GlobalKeyExtractor]: uses the same key for all incoming requests
//!
//! Check out the [custom_key](https://github.com/AaronErhardt/actix-governor/blob/main/examples/custom_key.rs) example to see how a custom key extractor can be implemented.
//!
//! # Add x-ratelimit headers
//!
//! By default, `x-ratelimit-after` is enable but if you want to enable `x-ratelimit-limit` and `x-ratelimit-remaining` use [`with_headers`] method
//!
//! [`with_headers`]: crate::GovernorConfigBuilder::with_headers
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
    fmt::Display,
    hash::Hash,
    net::IpAddr,
    num::NonZeroU32,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use actix_http::header::HeaderName;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::Method;
use actix_web::{body::MessageBody, error, Error};
use futures::future;
use governor::middleware::StateInformationMiddleware;

const DEFAULT_PERIOD: Duration = Duration::from_millis(500);
const DEFAULT_BURST_SIZE: u32 = 8;

/// Generic structure of what is needed to extract a rate-limiting key from an incoming request.
pub trait KeyExtractor: Clone {
    /// The type of the key.
    type Key: Clone + Hash + Eq;

    /// The type of the error that can occur if key extraction from the request fails.
    type KeyExtractionError: Display;

    #[cfg(feature = "log")]
    /// Name of this extractor (only used in logs).
    fn name(&self) -> &'static str;

    /// Extraction method
    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError>;

    #[cfg(feature = "log")]
    /// Value of the extracted key (only used in logs).
    fn key_name(&self, _key: &Self::Key) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A [KeyExtractor] that uses peer IP as key. **This is the default key extractor and [it may no do want you want](PeerIpKeyExtractor).**
///
/// **Warning:** this key extractor enforces rate limiting based on the **_peer_ IP address**.
///
/// This means that if your app is deployed behind a reverse proxy, the peer IP address will _always_ be the proxy's IP address.
/// In this case, rate limiting will be applied to _all_ incoming requests as if they were from the same user.
///
/// If this is not the behavior you want, you may:
/// - implement your own [KeyExtractor] that tries to get IP from the `Forwarded` or `X-Forwarded-For` headers that most reverse proxies set
/// - make absolutely sure that you only trust these headers when the peer IP is the IP of your reverse proxy (otherwise any user could set them to fake its IP)
pub struct PeerIpKeyExtractor;

impl KeyExtractor for PeerIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = &'static str;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "peer IP"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        req.peer_addr()
            .map(|socket| socket.ip())
            .ok_or("Could not extract peer IP address from request")
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A [KeyExtractor] that allow to do rate limiting for all incoming requests. This is useful if you want to hard-limit the HTTP load your app can handle.
pub struct GlobalKeyExtractor;

impl KeyExtractor for GlobalKeyExtractor {
    type Key = ();
    type KeyExtractionError = &'static str;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "global"
    }

    fn extract(&self, _req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        Ok(())
    }

    #[cfg(feature = "log")]
    fn key_name(&self, _key: &Self::Key) -> Option<String> {
        None
    }
}

/// Helper struct for building a configuration for the governor middleware.
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
///
/// with x-ratelimit headers
///
/// ```rust
/// use actix_governor::GovernorConfigBuilder;
///
/// let config = GovernorConfigBuilder::default()
///     .per_second(60)
///     .burst_size(10)
///     .with_headers() // Add this
///     .finish()
///     .unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernorConfigBuilder<K: KeyExtractor> {
    period: Duration,
    burst_size: u32,
    methods: Option<Vec<Method>>,
    key_extractor: K,
    with_headers: bool,
}

impl Default for GovernorConfigBuilder<PeerIpKeyExtractor> {
    /// The default configuration which is suitable for most services.
    /// Allows burst with up to eight requests and replenishes one element after 500ms, based on peer IP.
    /// The values can be modified by calling other methods on this struct.
    fn default() -> Self {
        Self::const_default()
    }
}

impl GovernorConfigBuilder<PeerIpKeyExtractor> {
    pub const fn const_default() -> Self {
        GovernorConfigBuilder {
            period: DEFAULT_PERIOD,
            burst_size: DEFAULT_BURST_SIZE,
            methods: None,
            key_extractor: PeerIpKeyExtractor,
            with_headers: false,
        }
    }
    /// Set the interval after which one element of the quota is replenished.
    ///
    /// **The interval must not be zero.**
    pub const fn const_period(mut self, duration: Duration) -> Self {
        self.period = duration;
        self
    }
    /// Set the interval after which one element of the quota is replenished in seconds.
    ///
    /// **The interval must not be zero.**
    pub const fn const_per_second(mut self, seconds: u64) -> Self {
        self.period = Duration::from_secs(seconds);
        self
    }
    /// Set the interval after which one element of the quota is replenished in milliseconds.
    ///
    /// **The interval must not be zero.**
    pub const fn const_per_millisecond(mut self, milliseconds: u64) -> Self {
        self.period = Duration::from_millis(milliseconds);
        self
    }
    /// Set the interval after which one element of the quota is replenished in nanoseconds.
    ///
    /// **The interval must not be zero.**
    pub const fn const_per_nanosecond(mut self, nanoseconds: u64) -> Self {
        self.period = Duration::from_nanos(nanoseconds);
        self
    }
    /// Set quota size that defines how many requests can occur
    /// before the governor middleware starts blocking requests from an IP address and
    /// clients have to wait until the elements of the quota are replenished.
    ///
    /// **The burst_size must not be zero.**
    pub const fn const_burst_size(mut self, burst_size: u32) -> Self {
        self.burst_size = burst_size;
        self
    }
}

impl<K: KeyExtractor> GovernorConfigBuilder<K> {
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
    /// By default this is all methods.
    pub fn methods(&mut self, methods: Vec<Method>) -> &mut Self {
        self.methods = Some(methods);
        self
    }

    /// Set the key extractor this configuration should use.
    /// By default this is using the [PeerIpKeyExtractor].
    pub fn key_extractor<K2: KeyExtractor>(
        &mut self,
        key_extractor: K2,
    ) -> GovernorConfigBuilder<K2> {
        GovernorConfigBuilder {
            period: self.period,
            burst_size: self.burst_size,
            methods: self.methods.to_owned(),
            key_extractor,
            with_headers: self.with_headers,
        }
    }

    /// Set x-ratelimit headers to response the headers is
    /// - `x-ratelimit-limit`     - Request limit
    /// - `x-ratelimit-remaining` - The number of requests left for the time window
    /// - `x-ratelimit-after`     - Number of seconds in which the API will become available after its rate limit has been exceeded
    ///
    /// By default only `x-ratelimit-after` is used
    pub fn with_headers(&mut self) -> &mut Self {
        self.with_headers = true;
        self
    }

    /// Finish building the configuration and return the configuration for the middleware.
    /// Returns `None` if either burst size or period interval are zero.
    pub fn finish(&mut self) -> Option<GovernorConfig<K>> {
        if self.burst_size != 0 && self.period.as_nanos() != 0 {
            Some(GovernorConfig {
                key_extractor: self.key_extractor.clone(),
                limiter: Arc::new(
                    RateLimiter::keyed(
                        Quota::with_period(self.period)
                            .unwrap()
                            .allow_burst(NonZeroU32::new(self.burst_size).unwrap()),
                    )
                    .with_middleware::<StateInformationMiddleware>(),
                ),
                methods: self.methods.clone(),
                with_headers: self.with_headers,
            })
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
/// Configuration for the Governor middleware.
pub struct GovernorConfig<K: KeyExtractor> {
    key_extractor: K,
    limiter: Arc<
        RateLimiter<
            K::Key,
            DefaultKeyedStateStore<K::Key>,
            DefaultClock,
            StateInformationMiddleware,
        >,
    >,
    methods: Option<Vec<Method>>,
    with_headers: bool,
}

impl Default for GovernorConfig<PeerIpKeyExtractor> {
    /// The default configuration which is suitable for most services.
    /// Allows bursts with up to eight requests and replenishes one element after 500ms, based on peer IP.
    fn default() -> Self {
        GovernorConfigBuilder::default().finish().unwrap()
    }
}

impl GovernorConfig<PeerIpKeyExtractor> {
    /// A default configuration for security related services.
    /// Allows bursts with up to two requests and replenishes one element after four seconds, based on peer IP.
    ///
    /// This prevents brute-forcing passwords or security tokens
    /// yet allows to quickly retype a wrong password once before the quota is exceeded.
    pub fn secure() -> Self {
        GovernorConfigBuilder {
            period: Duration::from_secs(4),
            burst_size: 2,
            methods: None,
            key_extractor: PeerIpKeyExtractor,
            with_headers: false, // false because before adding it was like this
        }
        .finish()
        .unwrap()
    }
}

/// Governor middleware factory.
pub struct Governor<K: KeyExtractor> {
    key_extractor: K,
    limiter: Arc<
        RateLimiter<
            K::Key,
            DefaultKeyedStateStore<K::Key>,
            DefaultClock,
            StateInformationMiddleware,
        >,
    >,
    methods: Option<Vec<Method>>,
    with_headers: bool,
}

impl<K: KeyExtractor> Governor<K> {
    /// Create new governor middleware factory from configuration.
    pub fn new(config: &GovernorConfig<K>) -> Self {
        Governor {
            key_extractor: config.key_extractor.clone(),
            limiter: config.limiter.clone(),
            methods: config.methods.clone(),
            with_headers: config.with_headers,
        }
    }
}

impl<S, B, K> Transform<S, ServiceRequest> for Governor<K>
where
    K: KeyExtractor,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = GovernorMiddleware<S, K>;
    type InitError = ();
    type Future = future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(GovernorMiddleware::<S, K> {
            service: Rc::new(RefCell::new(service)),
            key_extractor: self.key_extractor.clone(),
            limiter: self.limiter.clone(),
            methods: self.methods.clone(),
            with_headers: self.with_headers,
        })
    }
}

pub struct GovernorMiddleware<S, K: KeyExtractor> {
    service: std::rc::Rc<std::cell::RefCell<S>>,
    key_extractor: K,
    limiter: Arc<
        RateLimiter<
            K::Key,
            DefaultKeyedStateStore<K::Key>,
            DefaultClock,
            StateInformationMiddleware,
        >,
    >,
    methods: Option<Vec<Method>>,
    with_headers: bool,
}

impl<S, B, K> Service<ServiceRequest> for GovernorMiddleware<S, K>
where
    K: KeyExtractor,
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

        // Use the provided key extractor to extract the rate limiting key from the request.
        match self.key_extractor.extract(&req) {
            // Extraction worked, let's check if rate limiting is needed.
            Ok(key) => match self.limiter.check_key(&key) {
                Ok(_positive) => {
                    let fut = self.service.call(req);
                    // let mut response = ...;
                    // Add x-ratelimit headers
                    // if self.with_headers {
                    //     response.headers_mut().insert(
                    //         HeaderName::from_static("x-ratelimit-limit"),
                    //         positive.quota().burst_size().get().into(),
                    //     );
                    //     response.headers_mut().insert(
                    //         HeaderName::from_static("x-ratelimit-remaining"),
                    //         positive.remaining_burst_capacity().into(),
                    //     );
                    // }

                    future::Either::Right(fut)
                }

                Err(negative) => {
                    let wait_time = negative
                        .wait_time_from(DefaultClock::default().now())
                        .as_secs();

                    #[cfg(feature = "log")]
                    {
                        let key_name = match self.key_extractor.key_name(&key) {
                            Some(n) => format!(" [{}]", &n),
                            None => "".to_owned(),
                        };
                        log::info!(
                            "Rate limit exceeded for {}{}, quota reset in {}s",
                            self.key_extractor.name(),
                            key_name,
                            &wait_time
                        );
                    }

                    let wait_time_str = wait_time.to_string();
                    let body = format!("Too many requests, retry in {}s", wait_time_str);
                    let mut response =
                        actix_web::HttpResponse::TooManyRequests().body(body.clone());

                    // Add x-ratelimit headers
                    // By default x-ratelimit-after is enable
                    response.headers_mut().insert(
                        HeaderName::from_static("x-ratelimit-after"),
                        wait_time.into(),
                    );
                    if self.with_headers {
                        response.headers_mut().insert(
                            HeaderName::from_static("x-ratelimit-limit"),
                            negative.quota().burst_size().get().into(),
                        );
                        response.headers_mut().insert(
                            HeaderName::from_static("x-ratelimit-remaining"),
                            0u32.into(), // If the state is negative the remaining is zero
                        );
                    }

                    future::Either::Left(future::err(
                        error::InternalError::from_response(body, response).into(),
                    ))
                }
            },

            // Extraction failed, stop right now with a HTTP 500 error.
            Err(e) => {
                future::Either::Left(future::err(error::ErrorInternalServerError(e.to_string())))
            }
        }
    }
}
