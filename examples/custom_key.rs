use actix_governor::{Governor, GovernorConfigBuilder, KeyExtractor};
use actix_web::dev::ServiceRequest;
use actix_web::{web, App, HttpServer, Responder};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

async fn index() -> impl Responder {
    "Hello world!"
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let trusted_reverse_proxy_ip = IpAddr::from_str("127.0.0.1").unwrap(); // You should get this from configuration

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RealIpKeyExtractor;

    impl KeyExtractor for RealIpKeyExtractor {
        type Key = IpAddr;
        type KeyExtractionError = &'static str;

        #[cfg(feature = "log")]
        fn name(&self) -> &'static str {
            "real IP"
        }

        fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
            // Get the reverse proxy IP that we put in app data
            let reverse_proxy_ip = req
                .app_data::<web::Data<IpAddr>>()
                .map(|ip| ip.get_ref().to_owned())
                .unwrap_or_else(|| IpAddr::from_str("0.0.0.0").unwrap());

            let peer_ip = req.peer_addr().map(|socket| socket.ip());
            let connection_info = req.connection_info();

            match peer_ip {
                // The request is coming from the reverse proxy, we can trust the `Forwarded` or `X-Forwarded-For` headers
                Some(peer) if peer == reverse_proxy_ip => connection_info
                    .realip_remote_addr()
                    .ok_or("Could not extract real IP address from request")
                    .and_then(|str| {
                        SocketAddr::from_str(str)
                            .map(|socket| socket.ip())
                            .or_else(|_| IpAddr::from_str(str))
                            .map_err(|_| "Could not extract real IP address from request")
                    }),
                // The request is not comming from the reverse proxy, we use peer IP
                _ => connection_info
                    .remote_addr()
                    .ok_or("Could not extract peer IP address from request")
                    .and_then(|str| {
                        SocketAddr::from_str(str)
                            .map_err(|_| "Could not extract peer IP address from request")
                    })
                    .map(|socket| socket.ip()),
            }
        }

        #[cfg(feature = "log")]
        fn key_name(&self, key: &Self::Key) -> Option<String> {
            Some(key.to_string())
        }
    }

    // Allow bursts with up to five requests per IP address
    // and replenishes one element every two seconds
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(20)
        .burst_size(5)
        .key_extractor(RealIpKeyExtractor)
        .finish()
        .unwrap();

    HttpServer::new(move || {
        App::new()
            // Put the reverse proxy IP in app data so that Governor middleware can access it
            .app_data(web::Data::new(trusted_reverse_proxy_ip))
            // Enable Governor middleware
            .wrap(Governor::new(&governor_conf))
            // Route hello world service
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
