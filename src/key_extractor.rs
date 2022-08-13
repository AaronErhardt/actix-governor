use actix_web::ResponseError;
use actix_web::{dev::ServiceRequest, http::header::ContentType};
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::NotUntil;

use std::fmt::{Debug, Display};
use std::{hash::Hash, net::IpAddr};

/// Generic structure of what is needed to extract a rate-limiting key from an incoming request.
pub trait KeyExtractor: Clone {
    /// The type of the key.
    type Key: Clone + Hash + Eq;

    /// The type of the error that can occur if key extraction from the request fails.
    type KeyExtractionError: ResponseError + 'static;

    #[cfg(feature = "log")]
    /// Name of this extractor (only used in logs).
    fn name(&self) -> &'static str;

    /// Extraction method, will return [`KeyExtractionError`] response when the extract failed
    ///
    /// [`KeyExtractionError`]: KeyExtractor::KeyExtractionError
    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError>;

    /// The content you want to show it when the rate limit is exceeded.
    /// The [`NotUntil`] will be passed to it and it has enough information.
    /// You need to return the content and the content type.
    fn response_error_content(&self, negative: &NotUntil<QuantaInstant>) -> (String, ContentType) {
        let wait_time = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        (
            format!("Too many requests, retry in {}s", wait_time),
            ContentType::plaintext(),
        )
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

#[derive(Debug)]
/// The error of PeerIpKeyExtractor
pub struct PeerIpKeyExtractionError;

impl Display for PeerIpKeyExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Could not extract peer IP address from request")
    }
}

impl ResponseError for PeerIpKeyExtractionError {}

impl KeyExtractor for PeerIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = PeerIpKeyExtractionError;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "peer IP"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        req.peer_addr()
            .map(|socket| socket.ip())
            .ok_or(Self::KeyExtractionError {})
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A [KeyExtractor] that allow to do rate limiting for all incoming requests. This is useful if you want to hard-limit the HTTP load your app can handle.
pub struct GlobalKeyExtractor;

#[derive(Debug)]
/// A [KeyExtractor] default error, with 500 server error and plintext response ( a content is .0 )
pub struct GlobalKeyExtractionError<T: Display + Debug>(pub T);

impl<T: Display + Debug> Display for GlobalKeyExtractionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T: Display + Debug> ResponseError for GlobalKeyExtractionError<T> {}

impl KeyExtractor for GlobalKeyExtractor {
    type Key = ();
    type KeyExtractionError = GlobalKeyExtractionError<&'static str>;

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
