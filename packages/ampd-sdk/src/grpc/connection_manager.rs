use ampd::url::Url;
use error_stack::{Result, ResultExt as _};
use report::ResultExt;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tonic::transport;
use tracing::{error, info, warn};

use crate::future::RetryPolicy;
use crate::grpc::error::{AppError, Error};
use crate::grpc::utils::{ClientMessage, ConnectionHandle, ConnectionState};

// TODO: make these configurable
const DEFAULT_RETRY_POLICY: RetryPolicy = RetryPolicy::RepeatConstant {
    sleep: Duration::from_millis(100),
    max_attempts: 3,
};
const DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);
const KEEPALIVE_WHILE_IDLE: bool = true;

/// Connection manager that handles connection state and retries.
///
/// This is a multi-producer single consumer pattern:
/// - The manager maintains the connection state via a watch channel
/// - Multiple clients can subscribe to connection state changes
/// - Clients communicate back to the manager via mpsc channel
/// - The manager handles connection retries and failure recovery
#[derive(Debug)]
pub struct ConnectionManager {
    url: Url,
    connection_state: watch::Sender<ConnectionState>,
    message_receiver: mpsc::Receiver<ClientMessage>,
    retry_policy: RetryPolicy,
}

impl ConnectionManager {
    pub fn new(url: &str) -> Result<(Self, ConnectionHandle), Error> {
        let url = Url::new_sensitive(url).change_context(AppError::InvalidUrl.into())?;

        let (state_sender, state_receiver) = watch::channel(ConnectionState::Disconnected);
        let (msg_sender, msg_receiver) = mpsc::channel(100);

        let handle = ConnectionHandle {
            connection_receiver: state_receiver,
            message_sender: msg_sender,
        };

        let manager = Self {
            url,
            connection_state: state_sender,
            message_receiver: msg_receiver,
            retry_policy: DEFAULT_RETRY_POLICY,
        };

        Ok((manager, handle))
    }

    pub async fn run(mut self) -> Result<(), Error> {
        info!("starting the connection manager");
        let _ = self.connect().await;

        while let Some(message) = self.message_receiver.recv().await {
            match message {
                ClientMessage::ConnectionFailed(details) => {
                    warn!("client reported connection failure: {}", details);
                    self.handle_connection_failure().await;
                }
            }
        }

        Ok(())
    }

    async fn connect(&mut self) -> Result<(), Error> {
        let endpoint: transport::Endpoint = self.url.as_str().parse().into_report()?;
        let endpoint = endpoint
            .connect_timeout(DEFAULT_INITIAL_TIMEOUT)
            .timeout(DEFAULT_RPC_TIMEOUT)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(KEEPALIVE_WHILE_IDLE)
            .http2_keep_alive_interval(KEEPALIVE_TIME);

        match endpoint.connect().await {
            Ok(channel) => {
                info!("successfully connected to ampd gRPC server");
                let _ = self
                    .connection_state
                    .send(ConnectionState::Connected(channel));
                Ok(())
            }
            Err(status) => {
                let _ = self.connection_state.send(ConnectionState::Disconnected);
                warn!(err = ?status, "reconnecting to the ampd gRPC server failed");
                Err(status).into_report()
            }
        }
    }

    async fn handle_connection_failure(&mut self) {
        let _ = self.connection_state.send(ConnectionState::Reconnecting);

        let max_attempts = self.retry_policy.max_attempts();
        let mut attempts = 0u64;

        while attempts < max_attempts {
            attempts = attempts.saturating_add(1);

            if let Some(delay) = self.retry_policy.delay() {
                tokio::time::sleep(delay).await;
            }

            info!("reconnection attempt {} of {}", attempts, max_attempts);
            let _ = self.connect().await;

            if matches!(
                *self.connection_state.borrow(),
                ConnectionState::Connected(_)
            ) {
                return;
            }
        }

        error!("failed to reconnect after {} attempts", max_attempts);
        let _ = self.connection_state.send(ConnectionState::Disconnected);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    async fn test_setup() -> (ConnectionManager, ConnectionHandle, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("https://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    drop(stream);
                });
            }
        });

        let (manager, handle) = ConnectionManager::new(&server_url).unwrap();

        (manager, handle, server_url)
    }

    #[tokio::test]
    async fn connection_manager_should_start_disconnected() {
        let (_, handle, _) = test_setup().await;

        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));
    }

    #[tokio::test]
    async fn connection_manager_should_connect_successfully() {
        let (manager, handle, _) = test_setup().await;
        let manager_task = tokio::spawn(async move { manager.run().await });

        let mut receiver = handle.connection_receiver.clone();

        let result = timeout(Duration::from_secs(1), receiver.changed()).await;
        assert!(result.is_ok());

        assert!(matches!(*receiver.borrow(), ConnectionState::Connected(_)));

        manager_task.abort();
    }

    #[tokio::test]
    async fn connection_manager_should_handle_client_failure_reports() {
        let (manager, handle, _) = test_setup().await;
        let manager_task = tokio::spawn(async move { manager.run().await });

        let mut receiver = handle.connection_receiver.clone();
        let _ = timeout(Duration::from_secs(1), receiver.changed()).await;

        handle
            .message_sender
            .send(ClientMessage::ConnectionFailed(
                "test error from client".to_string(),
            ))
            .await
            .unwrap();

        let result = timeout(Duration::from_millis(100), receiver.changed()).await;
        assert!(result.is_ok());
        assert!(matches!(*receiver.borrow(), ConnectionState::Reconnecting));

        let result = timeout(Duration::from_millis(200), receiver.changed()).await;
        assert!(result.is_ok());
        assert!(matches!(*receiver.borrow(), ConnectionState::Connected(_)));

        manager_task.abort();
    }

    #[tokio::test]
    async fn connection_manager_should_handle_invalid_url() {
        let result = ConnectionManager::new("invalid-url");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::App(AppError::InvalidUrl)
        ));
    }
}
