use actix_web::dev::ServiceRequest;
use std::{fmt::Display, hash::Hash, net::IpAddr};

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

    /// Error function, will pass [`Self::KeyExtractionError`] to it to return the response error
    /// when the [`Self::extract`] failed [Read more]
    ///
    /// [Read more]: https://docs.rs/actix-web/4.1.0/actix_web/error/index.html#functions
    fn response_error(&self, err: Self::KeyExtractionError) -> actix_web::Error {
        actix_web::error::ErrorInternalServerError(err.to_string())
    }

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
