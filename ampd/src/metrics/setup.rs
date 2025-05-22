use std::sync::Arc;
use tokio::sync::mpsc;
use crate::metrics::client::MetricsClient;
use crate::metrics::server::MetricsServer;

const METRICS_CHANNEL_CAPACITY: usize = 1000;

pub fn create_metrics() -> Result<(MetricsClient, Arc<MetricsServer>), prometheus::Error> {
    let (tx, rx) = mpsc::channel(METRICS_CHANNEL_CAPACITY);
    let client = MetricsClient::new(tx);
    let server = Arc::new(MetricsServer::new()?);
    tokio::spawn({
        let server_clone = Arc::clone(&server);
        async move {
            server_clone.run(rx).await;
        }
    });
    
    Ok((client, server))
} 
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;
    
    #[tokio::test]
    async fn test_create_metrics_returns_valid_components() {
        let result = create_metrics();
        assert!(result.is_ok(), "create_metrics should succeed");
        let (client, server) = result.unwrap();
        let metrics = server.gather().expect("Failed to gather metrics");
        assert!(metrics.contains("blocks_received 0"), "Initial metrics should show 0 blocks");
    }

    #[tokio::test]
    async fn test_client_server_communication() {
        let (client, server) = create_metrics().expect("Failed to create metrics");
        for _ in 0..5 {
            client.inc_block_received().expect("Failed to increment blocks received");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let metrics = server.gather().expect("Failed to gather metrics");
        assert!(metrics.contains("blocks_received 5"), 
                "Metrics should show 5 blocks after increments");
    }
    #[tokio::test]
    async fn test_client_clone() {
        let (client, server) = create_metrics().expect("Failed to create metrics");
        let client_clone = client.clone();
        client.inc_block_received().expect("Failed to increment with original client");
        client_clone.inc_block_received().expect("Failed to increment with cloned client");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let metrics = server.gather().expect("Failed to gather metrics");
        assert!(metrics.contains("blocks_received 2"), 
                "Metrics should show 2 blocks after increments from both clients");
    }
}