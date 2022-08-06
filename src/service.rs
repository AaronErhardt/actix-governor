use actix_web::dev::{Service, ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::{body::MessageBody, error, Error};
use futures::future;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::{NoOpMiddleware, StateInformationMiddleware};

use std::future::Future;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{GovernorMiddleware, KeyExtractor};

impl<S, B, K> Service<ServiceRequest> for GovernorMiddleware<S, K, NoOpMiddleware>
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
                Ok(_) => {
                    let fut = self.service.call(req);
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

                    let body = format!("{{\"ok\":false,\"error_code\":429,\"description\":\"Too Many Requests: retry after {wait_time}s\"}}");
                    let response = actix_web::HttpResponse::TooManyRequests()
                        .insert_header(("content-type", "application/json"))
                        .insert_header(("x-ratelimit-after", wait_time))
                        .body(body.clone());
                    future::Either::Left(future::err(
                        error::InternalError::from_response(body, response).into(),
                    ))
                }
            },

            // Extraction failed, stop right now with a HTTP 401 error.
            Err(e) => future::Either::Left(future::err(error::ErrorUnauthorized(e.to_string()))),
        }
    }
}

pub struct RateLimitHeaderFut<F>
where
    F: Future,
{
    future: F,
    burst_size: u32,
    remaining_burst_capacity: u32,
}

impl<F, B> Future for RateLimitHeaderFut<F>
where
    F: Future<Output = Result<ServiceResponse<B>, actix_web::Error>> + Unpin,
    B: MessageBody,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.future), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(response) => Poll::Ready(match response {
                Ok(mut response) => {
                    let headers = response.headers_mut();
                    headers.insert(
                        HeaderName::from_static("x-ratelimit-limit"),
                        self.burst_size.into(),
                    );
                    headers.insert(
                        HeaderName::from_static("x-ratelimit-remaining"),
                        self.remaining_burst_capacity.into(),
                    );
                    Ok(response)
                }
                Err(err) => Err(err),
            }),
        }
    }
}

pub struct WhitelistedHeaderFut<F>
where
    F: Future,
{
    future: F,
}

impl<F, B> Future for WhitelistedHeaderFut<F>
where
    F: Future<Output = Result<ServiceResponse<B>, actix_web::Error>> + Unpin,
    B: MessageBody,
{
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Future::poll(Pin::new(&mut self.future), cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(response) => Poll::Ready(match response {
                Ok(mut response) => {
                    let headers = response.headers_mut();
                    headers.insert(
                        HeaderName::from_static("x-ratelimit-whitelisted"),
                        HeaderValue::from_static("true"),
                    );
                    Ok(response)
                }
                Err(err) => Err(err),
            }),
        }
    }
}

/// Implementation using rate limit headers
impl<S, B, K> Service<ServiceRequest> for GovernorMiddleware<S, K, StateInformationMiddleware>
where
    K: KeyExtractor,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = future::Either<
        future::Ready<Result<ServiceResponse<B>, actix_web::Error>>,
        future::Either<RateLimitHeaderFut<S::Future>, WhitelistedHeaderFut<S::Future>>,
    >;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(configured_methods) = &self.methods {
            if !configured_methods.contains(req.method()) {
                // The request method is not configured, we're ignoring this one.
                let fut = self.service.call(req);
                return future::Either::Right(future::Either::Right(WhitelistedHeaderFut {
                    future: fut,
                }));
            }
        }

        // Use the provided key extractor to extract the rate limiting key from the request.
        match self.key_extractor.extract(&req) {
            // Extraction worked, let's check if rate limiting is needed.
            Ok(key) => match self.limiter.check_key(&key) {
                Ok(snapshot) => {
                    let fut = self.service.call(req);
                    future::Either::Right(future::Either::Left(RateLimitHeaderFut {
                        future: fut,
                        burst_size: snapshot.quota().burst_size().get(),
                        remaining_burst_capacity: snapshot.remaining_burst_capacity(),
                    }))
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

                    let body = format!("{{\"ok\":false,\"error_code\":429,\"description\":\"Too Many Requests: retry after {wait_time}s\"}}");
                    let response = actix_web::HttpResponse::TooManyRequests()
                        .insert_header(("content-type", "application/json"))
                        .insert_header(("x-ratelimit-after", wait_time))
                        .insert_header(("x-ratelimit-limit", negative.quota().burst_size().get()))
                        .insert_header(("x-ratelimit-remaining", 0))
                        .body(body.clone());
                    future::Either::Left(future::err(
                        error::InternalError::from_response(body, response).into(),
                    ))
                }
            },

            // Extraction failed, stop right now with a HTTP 401 error.
            Err(e) => future::Either::Left(future::err(error::ErrorUnauthorized(e.to_string()))),
        }
    }
}
