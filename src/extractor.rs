use std::fmt::{Debug, Display, Formatter};

use actix_http::{HttpMessage, Payload};
use actix_web::{FromRequest, HttpRequest, ResponseError};
use futures::future::Ready;

use crate::{GovernorResult, KeyExtractor, PeerIpKeyExtractor};

/// Error returned when there's no governor middleware configured.
#[derive(Debug)]
pub struct ExtractorError;

impl Display for ExtractorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "No governor middleware found")
    }
}

impl ResponseError for ExtractorError {}

/// Extractor for governor rate limit results.
///
/// To use this extractor, don't forget to set [`GovernorConfig`](crate::GovernorConfig) to permissive,
/// or the request will be rejected before reaching your handler.
pub struct GovernorExtractor<K: KeyExtractor = PeerIpKeyExtractor>(
    pub GovernorResult<K::KeyExtractionError>,
);

impl<K: KeyExtractor> FromRequest for GovernorExtractor<K> {
    type Error = ExtractorError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        req.extensions_mut()
            .remove::<GovernorResult<K::KeyExtractionError>>()
            .map_or_else(
                || futures::future::err(ExtractorError),
                |result| futures::future::ok(GovernorExtractor(result)),
            )
    }
}
