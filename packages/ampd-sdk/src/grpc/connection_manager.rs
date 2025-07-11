use ampd::url::Url;
use error_stack::{Result, ResultExt as _};
use report::ResultExt;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tonic::transport;
use tracing::{error, info, warn};

use crate::future::{with_retry, RetryPolicy};
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
        if let Err(e) = self.connect().await {
            warn!(err = ?e, "initial connection failed, will retry on client requests");
        }

        while let Some(message) = self.message_receiver.recv().await {
            match message {
                ClientMessage::ConnectionFailed(details) => {
                    warn!("client reported connection failure: {}", details);
                    self.handle_connection_failure().await?
                }
            }
        }

        Ok(())
    }

    async fn connect(&self) -> Result<(), Error> {
        let endpoint: transport::Endpoint = self.url.as_str().parse().into_report()?;
        let endpoint = endpoint
            .connect_timeout(DEFAULT_INITIAL_TIMEOUT)
            .timeout(DEFAULT_RPC_TIMEOUT)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(KEEPALIVE_WHILE_IDLE)
            .http2_keep_alive_interval(KEEPALIVE_TIME);

        match endpoint.connect().await {
            Ok(channel) => {
                self.connection_state
                    .send(ConnectionState::Connected(channel))
                    .into_report()?;
                Ok(())
            }
            Err(status) => {
                let status_error = Err(status).into_report();
                if self
                    .connection_state
                    .send(ConnectionState::Disconnected)
                    .is_err()
                {
                    return status_error
                        .attach_printable("connection failed and could not notify clients");
                };
                status_error
            }
        }
    }

    async fn handle_connection_failure(&self) -> Result<(), Error> {
        self.connection_state
            .send(ConnectionState::Reconnecting)
            .into_report()?;

        match with_retry(|| self.connect(), self.retry_policy).await {
            Ok(()) => {
                info!("successfully reconnected after failure");
                Ok(())
            }
            Err(error_report) => {
                error!(err = ?error_report, "failed to reconnect after max attempts");
                let retry_error = Err(error_report);
                if self
                    .connection_state
                    .send(ConnectionState::Disconnected)
                    .is_err()
                {
                    return retry_error
                        .attach_printable("connection failed and could not notify clients");
                };
                retry_error
            }
        }
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
    async fn connection_manager_should_remain_diconnected_with_wrong_url() {
        let (manager, handle) = ConnectionManager::new("https://localhost:1").unwrap();
        let manager_task = tokio::spawn(async move { manager.run().await });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));

        manager_task.abort();
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
    async fn connection_manager_should_fail_after_max_retries() {
        let (manager, handle) = ConnectionManager::new("https://localhost:1").unwrap();
        let manager_task = tokio::spawn(async move { manager.run().await });

        let mut receiver = handle.connection_receiver.clone();

        handle
            .message_sender
            .send(ClientMessage::ConnectionFailed("test".to_string()))
            .await
            .unwrap();

        let _ = timeout(Duration::from_millis(100), receiver.changed()).await;
        assert!(matches!(*receiver.borrow(), ConnectionState::Reconnecting));

        let _ = timeout(Duration::from_millis(300), receiver.changed()).await;
        assert!(matches!(*receiver.borrow(), ConnectionState::Disconnected));

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
