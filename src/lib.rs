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

const DEFAULT_DURATION: Duration = Duration::from_secs(10);
const DEFAULT_QUOTA_SIZE: Option<NonZeroU32> = NonZeroU32::new(10);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct GovernorConfigBuilder {
    pub quota_duration: Duration,
    pub quota_size: NonZeroU32,
}

impl Default for GovernorConfigBuilder {
    fn default() -> Self {
        GovernorConfigBuilder {
            quota_duration: DEFAULT_DURATION,
            quota_size: DEFAULT_QUOTA_SIZE.unwrap(),
        }
    }
}

impl GovernorConfigBuilder {
    pub fn with_duration(self, duration: Duration) -> Self {
        GovernorConfigBuilder {
            quota_duration: duration,
            quota_size: self.quota_size,
        }
    }
    pub fn with_duration_in_secs(self, seconds: u64) -> Self {
        GovernorConfigBuilder {
            quota_duration: Duration::from_secs(seconds),
            quota_size: self.quota_size,
        }
    }
    pub fn with_duration_in_millis(self, millis: u64) -> Self {
        GovernorConfigBuilder {
            quota_duration: Duration::from_millis(millis),
            quota_size: self.quota_size,
        }
    }
    pub fn with_size(self, size: NonZeroU32) -> Self {
        GovernorConfigBuilder {
            quota_duration: self.quota_duration,
            quota_size: size,
        }
    }
    pub fn finish(self) -> GovernorConfig {
        GovernorConfig {
            limiter: Arc::new(RateLimiter::keyed(
                Quota::with_period(self.quota_duration)
                    .unwrap_or_else(|| Quota::with_period(Duration::from_secs(10)).unwrap())
                    .allow_burst(self.quota_size),
            )),
        }
    }
}

#[derive(Clone)]
pub struct GovernorConfig {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

pub struct Governor {
    limiter: Arc<RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock>>,
}

impl Governor {
    pub fn from_config(config: &GovernorConfig) -> Governor {
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
                    "Coulnd't find peer address",
                ))
            });
        };

        // clone to prevent moving values into the closure
        let mut srv = self.service.clone();
        let limiter = self.limiter.clone();

        Box::pin(async move {
            match limiter.check_key(&ip) {
                Ok(_) => {
                    log::info!("allowing remote {}", &ip);
                    let res = srv.call(req).await?;
                    Ok(res)
                }
                Err(negative) => {
                    let wait_time = negative
                        .wait_time_from(DefaultClock::default().now())
                        .as_secs();
                    log::info!("Limit exceeded for client: {} for {}", &ip, &wait_time);
                    let mut response = actix_web::HttpResponse::TooManyRequests();
                    response
                        .set_header(actix_web::http::header::RETRY_AFTER, wait_time.to_string());
                    Err(response.into())
                }
            }
        })
    }
}
