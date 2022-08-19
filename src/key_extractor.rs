use actix_http::StatusCode;
use actix_web::{dev::ServiceRequest, http::header::ContentType};
use actix_web::{HttpResponse, HttpResponseBuilder, ResponseError};
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::NotUntil;

use std::fmt::{Debug, Display};
use std::{hash::Hash, net::IpAddr};

/// Generic structure of what is needed to extract a rate-limiting key from an incoming request.
///
/// ## Example
/// ```rust
/// use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
/// use actix_web::ResponseError;
/// use actix_web::dev::ServiceRequest;
///
/// #[derive(Clone)]
/// struct Foo;
///
/// // will return 500 error and 'Extract error' as content
/// impl KeyExtractor for Foo {
///     type Key = ();
///     type KeyExtractionError = SimpleKeyExtractionError<&'static str>;
///
///     fn extract(&self, _req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
///         Err(SimpleKeyExtractionError::new("Extract error"))
///     }
/// }
/// ```
///
/// For more see [`custom_key_bearer`](https://github.com/AaronErhardt/actix-governor/blob/main/examples/custom_key_bearer.rs) example
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
    /// You can calculate the time at which a caller can expect the next positive rate-limiting result by using [`NotUntil`].
    /// The [`HttpResponseBuilder`] allows you to build a fully customized [`HttpResponse`] in case of an error.
    /// # Example
    /// ```rust
    /// use actix_governor::{KeyExtractor, SimpleKeyExtractionError};
    /// use actix_web::ResponseError;
    /// use actix_web::dev::ServiceRequest;
    /// use governor::{NotUntil, clock::{Clock, QuantaInstant, DefaultClock}};
    /// use actix_web::{HttpResponse, HttpResponseBuilder};
    /// use actix_web::http::header::ContentType;
    ///
    ///
    /// #[derive(Clone)]
    /// struct Foo;
    ///
    /// // will return 500 error and 'Extract error' as content
    /// impl KeyExtractor for Foo {
    ///     type Key = ();
    ///     type KeyExtractionError = SimpleKeyExtractionError<&'static str>;
    ///
    ///     fn extract(&self, _req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
    ///         Err(SimpleKeyExtractionError::new("Extract error"))
    ///     }
    ///
    ///     fn exceed_rate_limit_response(
    ///             &self,
    ///             negative: &NotUntil<QuantaInstant>,
    ///             mut response: HttpResponseBuilder,
    ///         ) -> HttpResponse {
    ///             let wait_time = negative
    ///                 .wait_time_from(DefaultClock::default().now())
    ///                 .as_secs();
    ///             response
    ///                 .content_type(ContentType::plaintext())
    ///                 .body(format!("Too many requests, retry in {}s", wait_time))
    ///     }
    /// }
    /// ```
    fn exceed_rate_limit_response(
        &self,
        negative: &NotUntil<QuantaInstant>,
        mut response: HttpResponseBuilder,
    ) -> HttpResponse {
        let wait_time = negative
            .wait_time_from(DefaultClock::default().now())
            .as_secs();
        response
            .content_type(ContentType::plaintext())
            .body(format!("Too many requests, retry in {}s", wait_time))
    }

    #[cfg(feature = "log")]
    /// Value of the extracted key (only used in logs).
    fn key_name(&self, _key: &Self::Key) -> Option<String> {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// A [KeyExtractor] that allow to do rate limiting for all incoming requests. This is useful if you want to hard-limit the HTTP load your app can handle.
pub struct GlobalKeyExtractor;

#[derive(Debug)]
/// A simple struct to create  error, by default the status is  500 server error and content-type is plintext
pub struct SimpleKeyExtractionError<T: Display + Debug> {
    pub body: T,
    pub status_code: StatusCode,
    pub content_type: ContentType,
}

impl<T: Display + Debug> SimpleKeyExtractionError<T> {
    /// Create new instance by body
    ///
    /// # Example
    /// ```rust
    /// use actix_governor::SimpleKeyExtractionError;
    /// use actix_http::StatusCode;
    /// use actix_web::http::header::ContentType;
    ///
    /// let my_error = SimpleKeyExtractionError::new("Some error content");
    ///
    /// assert_eq!(my_error.body, "Some error content");
    /// assert_eq!(my_error.content_type, ContentType::plaintext());
    /// assert_eq!(my_error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
    /// ```
    pub fn new(body: T) -> Self {
        Self {
            body,
            status_code: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: ContentType::plaintext(),
        }
    }

    /// Set a new status code, the default is [`StatusCode::INTERNAL_SERVER_ERROR`]
    ///
    /// # Example
    /// ```rust
    /// use actix_governor::SimpleKeyExtractionError;
    /// use actix_http::StatusCode;
    /// use actix_web::http::header::ContentType;
    ///
    /// let my_error = SimpleKeyExtractionError::new("Some error content")
    ///         .set_status_code(StatusCode::FORBIDDEN);
    ///
    /// assert_eq!(my_error.body, "Some error content");
    /// assert_eq!(my_error.content_type, ContentType::plaintext());
    /// assert_eq!(my_error.status_code, StatusCode::FORBIDDEN);
    /// ```
    pub fn set_status_code(mut self, status_code: StatusCode) -> Self {
        self.status_code = status_code;
        Self { ..self }
    }

    /// Set a new content type, the default is `text/plain`
    ///
    /// # Example
    /// ```rust
    /// use actix_governor::SimpleKeyExtractionError;
    /// use actix_http::StatusCode;
    /// use actix_web::http::header::ContentType;
    ///
    /// let my_error = SimpleKeyExtractionError::new(r#"{"msg":"Some error content"}"#)
    ///         .set_content_type(ContentType::json());
    ///
    /// assert_eq!(my_error.body, r#"{"msg":"Some error content"}"#);
    /// assert_eq!(my_error.content_type, ContentType::json());
    /// assert_eq!(my_error.status_code, StatusCode::INTERNAL_SERVER_ERROR);
    /// ```
    pub fn set_content_type(mut self, content_type: ContentType) -> Self {
        self.content_type = content_type;
        Self { ..self }
    }
}

impl<T: Display + Debug> Display for SimpleKeyExtractionError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SimpleKeyExtractionError")
    }
}

impl<T: Display + Debug> ResponseError for SimpleKeyExtractionError<T> {
    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse<actix_http::body::BoxBody> {
        HttpResponseBuilder::new(self.status_code())
            .content_type(self.content_type.clone())
            .body(self.body.to_string())
    }
}

impl KeyExtractor for GlobalKeyExtractor {
    type Key = ();
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

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
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    #[cfg(feature = "log")]
    fn name(&self) -> &'static str {
        "peer IP"
    }

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        req.peer_addr().map(|socket| socket.ip()).ok_or_else(|| {
            SimpleKeyExtractionError::new("Could not extract peer IP address from request")
        })
    }

    #[cfg(feature = "log")]
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}
