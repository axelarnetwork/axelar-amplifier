use std::mem::discriminant;

use ampd::url::Url;
use error_stack::Result;
use report::ResultExt;
use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use tonic::transport;
use tracing::{error, info, warn};

use crate::future::{with_retry, RetryPolicy};

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to connect to the grpc endpoint")]
    GrpcConnection(#[from] transport::Error),

    #[error(transparent)]
    ClientNotificationFailed(#[from] watch::error::SendError<ConnectionState>),

    #[error(transparent)]
    SelfNotificationFailed(#[from] mpsc::error::SendError<ClientMessage>),

    #[error(transparent)]
    ConnectionStateReceiveFailed(#[from] watch::error::RecvError),

    #[error("invalid url")]
    InvalidUrl,

    #[error("connection pool disconnected")]
    ServerDisconnected(#[from] tokio::time::error::Elapsed),
}

// TODO: make these configurable
const DEFAULT_RETRY_POLICY: RetryPolicy = RetryPolicy::RepeatConstant {
    sleep: Duration::from_millis(100),
    max_attempts: 3,
};
const DEFAULT_SERVER_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(5);
const KEEPALIVE_TIME: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(3);
const KEEPALIVE_WHILE_IDLE: bool = true;
const MESSAGE_RECEIVER_CHANNEL_CAPACITY: usize = 100;

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
    connection_receiver: watch::Receiver<ConnectionState>,
    message_sender: mpsc::Sender<ClientMessage>,
    has_sent_disconnected_message: bool,
}

impl ConnectionHandle {
    /// This method encapsulates all the connection state management logic:
    /// - If connected, returns the channel immediately
    /// - If disconnected, inform clients
    /// - If reconnecting, waits for the connection to complete and returns the channel
    ///
    /// Clients should use this method instead of manually handling connection states.
    pub async fn get_connected_channel(&mut self) -> Result<transport::Channel, Error> {
        timeout(DEFAULT_SERVER_TIMEOUT, async {
            loop {
                let connection_state = self.connection_receiver.borrow_and_update().clone();

                match connection_state {
                    ConnectionState::Connected(channel) => {
                        self.has_sent_disconnected_message = false;
                        return Ok(channel);
                    }
                    ConnectionState::Disconnected => {
                        // Only send ConnectionFailed message if we haven't already sent one
                        if !self.has_sent_disconnected_message {
                            self.send_client_message(ClientMessage::ConnectionFailed(
                                "client requested connection while disconnected".to_string(),
                            ))
                            .await?;
                            self.has_sent_disconnected_message = true;
                        }

                        let mut receiver = self.connection_receiver.clone();
                        receiver.changed().await.into_report()?;
                    }
                    ConnectionState::Reconnecting => {
                        let mut receiver = self.connection_receiver.clone();
                        receiver.changed().await.into_report()?;
                    }
                }
            }
        })
        .await
        .into_report()?
    }

    pub async fn send_client_message(&self, message: ClientMessage) -> Result<(), Error> {
        self.message_sender.send(message).await.into_report()
    }

    pub fn connection_receiver(&self) -> watch::Receiver<ConnectionState> {
        self.connection_receiver.clone()
    }
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
    pub fn new(url: Url) -> (Self, ConnectionHandle) {
        let (state_sender, state_receiver) = watch::channel(ConnectionState::Disconnected);
        let (msg_sender, msg_receiver) = mpsc::channel(MESSAGE_RECEIVER_CHANNEL_CAPACITY);

        let handle = ConnectionHandle {
            connection_receiver: state_receiver,
            message_sender: msg_sender,
            has_sent_disconnected_message: false,
        };

        let pool = Self {
            url,
            connection_state: state_sender,
            message_receiver: msg_receiver,
            retry_policy: DEFAULT_RETRY_POLICY,
        };

        (pool, handle)
    }

    pub async fn run(mut self, token: CancellationToken) -> Result<(), Error> {
        if let Err(e) = self.connect().await {
            warn!(err = ?e, "initial connection failed, will retry on client requests");
        }

        loop {
            tokio::select! {
                message = self.message_receiver.recv() => {
                    match message {
                        Some(ClientMessage::ConnectionFailed(details)) => {
                            warn!("client reported connection failure: {}", details);
                            if let Err(e) = self.handle_connection_failure().await {
                                warn!(err = ?e, "reconnection attempt failed, will retry on next client request");
                            }
                        }
                        None => break,
                    }
                }
                _ = token.cancelled() => {
                    info!("connection pool shutting down due to cancellation");
                    break;
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
                self.notify_clients(ConnectionState::Connected(channel));
                Ok(())
            }
            Err(status) => Err(status).into_report(),
        }
    }

    async fn handle_connection_failure(&self) -> Result<(), Error> {
        self.notify_clients(ConnectionState::Reconnecting);

        match with_retry(|| self.connect(), self.retry_policy).await {
            Ok(()) => {
                info!("successfully reconnected after failure");
                Ok(())
            }
            Err(error_report) => {
                self.notify_clients(ConnectionState::Disconnected);
                Err(error_report)
            }
        }
    }

    fn notify_clients(&self, state: ConnectionState) {
        if let Err(error) = self.connection_state.send(state) {
            warn!(err = ?error, "failed to notify clients of state change");
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::time::{timeout, Duration};

    use super::*;

    async fn test_setup() -> (ConnectionPool, ConnectionHandle) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_url = format!("https://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    drop(stream);
                });
            }
        });

        let pool_url = Url::new_sensitive(&server_url).unwrap();
        let (pool, handle) = ConnectionPool::new(pool_url);

        (pool, handle)
    }

    #[tokio::test]
    async fn connection_pool_should_start_disconnected() {
        let (_, handle) = test_setup().await;

        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));
    }

    #[tokio::test]
    async fn connection_pool_should_remain_disconnected_with_wrong_url() {
        let (pool, handle) =
            ConnectionPool::new(Url::new_sensitive("https://localhost:1").unwrap());
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });

        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_connect_successfully() {
        let (pool, handle) = test_setup().await;
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });

        let mut receiver = handle.connection_receiver.clone();

        let result = timeout(Duration::from_secs(1), receiver.changed()).await;
        assert!(result.is_ok());

        assert!(matches!(*receiver.borrow(), ConnectionState::Connected(_)));

        pool_task.abort();
    }

    #[tokio::test]
    async fn connection_pool_should_handle_client_failure_reports() {
        let (pool, handle) = test_setup().await;
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });

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
        let (pool, handle) =
            ConnectionPool::new(Url::new_sensitive("https://localhost:1").unwrap());
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });

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
    async fn connection_pool_should_handle_multiple_connection_failed_messages() {
        let (pool, handle) =
            ConnectionPool::new(Url::new_sensitive("https://localhost:1").unwrap());
        let pool_task = tokio::spawn(async move { pool.run(CancellationToken::new()).await });

        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut test_handle = handle.clone();

        let first_result = tokio::time::timeout(
            Duration::from_millis(100),
            test_handle.get_connected_channel(),
        )
        .await;
        assert!(first_result.is_err());

        let second_result = tokio::time::timeout(
            Duration::from_millis(100),
            test_handle.get_connected_channel(),
        )
        .await;
        assert!(second_result.is_err());

        tokio::time::sleep(Duration::from_millis(500)).await;

        // The state should still be Disconnected after both calls
        assert!(matches!(
            *handle.connection_receiver.borrow(),
            ConnectionState::Disconnected
        ));

        pool_task.abort();
    }
}
