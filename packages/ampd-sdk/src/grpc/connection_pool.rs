use std::mem::discriminant;

use ampd::url::Url;
use error_stack::{Result, ResultExt as _};
use report::ResultExt;
use thiserror::Error;
use tokio::sync::watch::error::SendError;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tonic::transport;
use tracing::{error, info, warn};

use crate::future::{with_retry, RetryPolicy};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] transport::Error),

    #[error("failed to broadcast state to clients")]
    ClientNotificationFailed(#[from] SendError<ConnectionState>),

    #[error("invalid url")]
    InvalidUrl,
}

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

#[derive(Debug, Clone)]
pub enum ClientMessage {
    ConnectionFailed(String),
}

/// Represents the state of a gRPC connection to the AMPD server.
///
/// This enum is used by the connection pool to communicate the connection status to clients.
#[derive(Debug, Clone)]
pub enum ConnectionState {
    /// The connection is established and ready for service calls.
    /// Contains the active gRPC transport channel.
    Connected(transport::Channel),

    /// The connection is not available and no reconnection attempt is in progress.
    /// This is the initial state when the connection pool starts, or the final state after all reconnection attempts have failed.  
    Disconnected,

    /// A reconnection attempt is currently in progress.
    /// The connection pool is actively trying to re-establish the connection after a failure.
    /// Clients should wait for the next state change rather than immediately failing their requests.
    Reconnecting,
}

impl PartialEq for ConnectionState {
    fn eq(&self, other: &Self) -> bool {
        discriminant(self) == discriminant(other)
    }
}

/// A handle that provides access to connection state changes and allows sending
/// messages to the connection pool.
///
/// This struct is used by clients to:
/// - Monitor connection state changes via the `connection_receiver`
/// - Send messages (like connection failure reports) to the connection pool
/// - Coordinate with the connection pool for automatic reconnection
#[derive(Clone, Debug)]
pub struct ConnectionHandle {
    pub connection_receiver: watch::Receiver<ConnectionState>,
    pub message_sender: mpsc::Sender<ClientMessage>,
}

/// Connection pool that handles connection state and retries.
///
/// This is a multi-producer single consumer pattern:
/// - The pool maintains the connection state via a watch channel
/// - Multiple clients can subscribe to connection state changes
/// - Clients communicate back to the pool via mpsc channel
/// - The pool handles connection retries and failure recovery
#[derive(Debug)]
pub struct ConnectionPool {
    url: Url,
    connection_state: watch::Sender<ConnectionState>,
    message_receiver: mpsc::Receiver<ClientMessage>,
    retry_policy: RetryPolicy,
}

impl ConnectionPool {
    pub fn new(url: &str) -> Result<(Self, ConnectionHandle), Error> {
        let url = Url::new_sensitive(url).change_context(Error::InvalidUrl)?;

        let (state_sender, state_receiver) = watch::channel(ConnectionState::Disconnected);
        let (msg_sender, msg_receiver) = mpsc::channel(100);

        let handle = ConnectionHandle {
            connection_receiver: state_receiver,
            message_sender: msg_sender,
        };

        let pool = Self {
            url,
            connection_state: state_sender,
            message_receiver: msg_receiver,
            retry_policy: DEFAULT_RETRY_POLICY,
        };

        Ok((pool, handle))
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
                self.notify_clients(ConnectionState::Connected(channel), false)?;
                Ok(())
            }
            Err(status) => {
                self.notify_clients(ConnectionState::Disconnected, false)?;
                Err(status).into_report()
            }
        }
    }

    async fn handle_connection_failure(&self) -> Result<(), Error> {
        self.notify_clients(ConnectionState::Reconnecting, true)?;

        match with_retry(|| self.connect(), self.retry_policy).await {
            Ok(()) => {
                info!("successfully reconnected after failure");
                Ok(())
            }
            Err(error_report) => {
                self.notify_clients(ConnectionState::Disconnected, true)?;
                Err(error_report)
            }
        }
    }

    fn notify_clients(&self, state: ConnectionState, log_on_error: bool) -> Result<(), Error> {
        match self.connection_state.send(state) {
            Ok(()) => Ok(()),
            Err(send_error) => {
                if log_on_error {
                    warn!(err = ?send_error, "failed to notify clients of state change");
                    Ok(())
                } else {
                    Err(send_error).into_report()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::timeout;

    use super::*;

    async fn test_setup() -> (ConnectionPool, ConnectionHandle, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("https://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    drop(stream);
                });
            }
        });

        let (pool, handle) = ConnectionPool::new(&server_url).unwrap();

        (pool, handle, server_url)
    }

    #[tokio::test]
    async fn connection_pool_should_start_disconnected() {
        let (_, handle, _) = test_setup().await;

        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));
    }

    #[tokio::test]
    async fn connection_pool_should_remain_diconnected_with_wrong_url() {
        let (pool, handle) = ConnectionPool::new("https://localhost:1").unwrap();
        let pool_task = tokio::spawn(async move { pool.run().await });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_connect_successfully() {
        let (pool, handle, _) = test_setup().await;
        let pool_task = tokio::spawn(async move { pool.run().await });

        let mut receiver = handle.connection_receiver.clone();

        let result = timeout(Duration::from_secs(1), receiver.changed()).await;
        assert!(result.is_ok());

        assert!(matches!(*receiver.borrow(), ConnectionState::Connected(_)));

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_handle_client_failure_reports() {
        let (pool, handle, _) = test_setup().await;
        let pool_task = tokio::spawn(async move { pool.run().await });

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

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_fail_after_max_retries() {
        let (pool, handle) = ConnectionPool::new("https://localhost:1").unwrap();
        let pool_task = tokio::spawn(async move { pool.run().await });

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

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_handle_invalid_url() {
        let result = ConnectionPool::new("invalid-url");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err().current_context(),
            Error::InvalidUrl
        ));
    }
}
