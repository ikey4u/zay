use std::future::Future;

use thiserror::Error;
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{service::InterceptorLayer, transport::Server};

use super::{ServerAuthInterceptor, StartedDaemonService, proto};

const HEALTH_SERVICE_NAME: &str = "grpc.health.v1.Health";
const REFLECTION_V1_SERVICE_NAME: &str = "grpc.reflection.v1.ServerReflection";
const REFLECTION_V1ALPHA_SERVICE_NAME: &str =
    "grpc.reflection.v1alpha.ServerReflection";

#[derive(Debug, Error)]
pub enum DaemonServerError {
    #[error("failed to construct gRPC reflection service: {0}")]
    Reflection(#[from] tonic_reflection::server::Error),
    #[error("daemon gRPC server failed: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Serve the upstream StartedService, gRPC health protocol, and both reflection
/// protocol versions on an already-bound TCP listener.
///
/// Authentication is installed as a server-wide layer, matching Go's chained
/// unary/stream interceptors for daemon, health, and reflection calls alike.
pub async fn serve_started_with_shutdown<F>(
    listener: TcpListener,
    service: StartedDaemonService,
    secret: impl Into<std::sync::Arc<str>>,
    shutdown: F,
) -> Result<(), DaemonServerError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let (health_reporter, health_service) =
        tonic_health::server::health_reporter();
    health_reporter
        .set_service_status(
            proto::started_service_server::SERVICE_NAME,
            tonic_health::ServingStatus::Serving,
        )
        .await;

    let reflection_builder = || {
        tonic_reflection::server::Builder::configure()
            .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(
                tonic_health::pb::FILE_DESCRIPTOR_SET,
            )
            .with_service_name(proto::started_service_server::SERVICE_NAME)
            .with_service_name(HEALTH_SERVICE_NAME)
            .with_service_name(REFLECTION_V1_SERVICE_NAME)
            .with_service_name(REFLECTION_V1ALPHA_SERVICE_NAME)
    };
    let reflection_v1 = reflection_builder().build_v1()?;
    let reflection_v1alpha = reflection_builder().build_v1alpha()?;

    Server::builder()
        .layer(InterceptorLayer::new(ServerAuthInterceptor::new(secret)))
        .add_service(proto::started_service_server::StartedServiceServer::new(
            service,
        ))
        .add_service(health_service)
        .add_service(reflection_v1)
        .add_service(reflection_v1alpha)
        .serve_with_incoming_shutdown(
            TcpListenerStream::new(listener),
            shutdown,
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use tokio::{net::TcpListener, sync::oneshot};
    use tonic_health::pb::{
        HealthCheckRequest, health_check_response::ServingStatus,
        health_client::HealthClient,
    };
    use tonic_reflection::pb::v1::{
        ServerReflectionRequest,
        server_reflection_client::ServerReflectionClient,
        server_reflection_request::MessageRequest,
        server_reflection_response::MessageResponse,
    };

    use super::{
        HEALTH_SERVICE_NAME, REFLECTION_V1_SERVICE_NAME,
        REFLECTION_V1ALPHA_SERVICE_NAME, serve_started_with_shutdown,
    };
    use crate::daemon::{
        RemoteClientOptions, StartedDaemonService, StartedServiceOptions, proto,
    };

    #[tokio::test]
    async fn daemon_server_exposes_authenticated_health_and_reflection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            serve_started_with_shutdown(
                listener,
                StartedDaemonService::new(StartedServiceOptions::default()),
                "server secret",
                async move {
                    let _ = shutdown_rx.await;
                },
            )
            .await
            .unwrap();
        });

        let options = RemoteClientOptions {
            server_url: format!("http://{address}"),
            secret: "server secret".into(),
        };
        let channel = options.channel().unwrap();
        let mut health = HealthClient::with_interceptor(
            channel.clone(),
            options.auth_interceptor().unwrap(),
        );
        let response = health
            .check(HealthCheckRequest {
                service: proto::started_service_server::SERVICE_NAME.into(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.status, i32::from(ServingStatus::Serving));

        let mut unauthorized = HealthClient::new(channel.clone());
        let error = unauthorized
            .check(HealthCheckRequest {
                service: proto::started_service_server::SERVICE_NAME.into(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Unauthenticated);

        let mut reflection = ServerReflectionClient::with_interceptor(
            channel,
            options.auth_interceptor().unwrap(),
        );
        let request = ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        };
        let mut responses = reflection
            .server_reflection_info(stream::iter([request]))
            .await
            .unwrap()
            .into_inner();
        let response = responses.message().await.unwrap().unwrap();
        let MessageResponse::ListServicesResponse(services) =
            response.message_response.unwrap()
        else {
            panic!("reflection did not return a service list");
        };
        let mut names = services
            .service
            .into_iter()
            .map(|service| service.name)
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                proto::started_service_server::SERVICE_NAME,
                HEALTH_SERVICE_NAME,
                REFLECTION_V1_SERVICE_NAME,
                REFLECTION_V1ALPHA_SERVICE_NAME,
            ]
        );

        drop(reflection);
        drop(health);
        drop(unauthorized);
        let _ = shutdown_tx.send(());
        server.await.unwrap();
    }
}
