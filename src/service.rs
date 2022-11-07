use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::{body::MessageBody, Error};
use futures::{future, TryFutureExt};
use governor::clock::{Clock, DefaultClock};
use governor::middleware::{NoOpMiddleware, StateInformationMiddleware};

use actix_http::body::EitherBody;
use futures::future::{ok, Either, MapOk, Ready};
use std::future::Future;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::{GovernorMiddleware, KeyExtractor};

type ServiceFuture<S, B> = MapOk<
    <S as Service<ServiceRequest>>::Future,
    fn(ServiceResponse<B>) -> ServiceResponse<EitherBody<B>>,
>;

impl<S, B, K> Service<ServiceRequest> for GovernorMiddleware<S, K, NoOpMiddleware>
where
    K: KeyExtractor,
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = S::Error;
    type Future =
        Either<ServiceFuture<S, B>, Ready<Result<ServiceResponse<EitherBody<B>>, Self::Error>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(configured_methods) = &self.methods {
            if !configured_methods.contains(req.method()) {
                // The request method is not configured, we're ignoring this one.
                let fut = self.service.call(req);
                return Either::Left(fut.map_ok(|resp| resp.map_into_left_body()));
            }
        }

        // Use the provided key extractor to extract the rate limiting key from the request.
        match self.key_extractor.extract(&req) {
            // Extraction worked, let's check if rate limiting is needed.
            Ok(key) => match self.limiter.check_key(&key) {
                Ok(_) => {
                    let fut = self.service.call(req);
                    Either::Left(fut.map_ok(|resp| resp.map_into_left_body()))
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
                    let mut response_builder = actix_web::HttpResponse::TooManyRequests();
                    response_builder.insert_header(("x-ratelimit-after", wait_time));
                    let response = self
                        .key_extractor
                        .exceed_rate_limit_response(&negative, response_builder);

                    let response = req.into_response(response);
                    Either::Right(ok(response.map_into_right_body()))
                }
            },

            // Extraction failed, stop right now.
            Err(e) => Either::Right(future::err(e.into())),
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
    F: Future<Output = Result<ServiceResponse<EitherBody<B>>, Error>> + Unpin,
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
    F: Future<Output = Result<ServiceResponse<EitherBody<B>>, Error>> + Unpin,
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
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = S::Error;
    type Future = Either<
        Either<RateLimitHeaderFut<ServiceFuture<S, B>>, WhitelistedHeaderFut<ServiceFuture<S, B>>>,
        Ready<Result<ServiceResponse<EitherBody<B>>, Error>>,
    >;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if let Some(configured_methods) = &self.methods {
            if !configured_methods.contains(req.method()) {
                // The request method is not configured, we're ignoring this one.
                let fut = self.service.call(req);
                return Either::Left(Either::Right(WhitelistedHeaderFut {
                    future: fut.map_ok(|resp| resp.map_into_left_body()),
                }));
            }
        }

        // Use the provided key extractor to extract the rate limiting key from the request.
        match self.key_extractor.extract(&req) {
            // Extraction worked, let's check if rate limiting is needed.
            Ok(key) => match self.limiter.check_key(&key) {
                Ok(snapshot) => {
                    let fut = self.service.call(req);
                    Either::Left(Either::Left(RateLimitHeaderFut {
                        future: fut.map_ok(|resp| resp.map_into_left_body()),
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

                    let mut response_builder = actix_web::HttpResponse::TooManyRequests();
                    response_builder
                        .insert_header(("x-ratelimit-after", wait_time))
                        .insert_header(("x-ratelimit-limit", negative.quota().burst_size().get()))
                        .insert_header(("x-ratelimit-remaining", 0));
                    let response = self
                        .key_extractor
                        .exceed_rate_limit_response(&negative, response_builder);

                    let response = req.into_response(response);
                    Either::Right(ok(response.map_into_right_body()))
                }
            },

            // Extraction failed, stop right now.
            Err(e) => Either::Right(future::err(e.into())),
        }
    }
}
