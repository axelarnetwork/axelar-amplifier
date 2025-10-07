use std::env;

use ampd::url::Url;
use ampd_sdk::grpc::client::{GrpcClient, TaskClient};
use ampd_sdk::grpc::connection_pool::ConnectionPool;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = env::var("AMPD_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let ampd_url = Url::new_sensitive(&url)?;

    println!("Attempting to connect to AMPD server");

    let (pool, handle) = ConnectionPool::new(ampd_url);
    let token = CancellationToken::new();
    tokio::spawn(async move {
        let _ = pool.run(token.clone()).await;
    });

    let mut client = GrpcClient::new(handle);

    println!("Connected to AMPD server");

    let mut event_stream = client.subscribe(vec![], true).await?;

    println!("Subscribed to events. Listening...");

    while let Some(event_result) = event_stream.next().await {
        match event_result {
            Ok(event) => {
                println!("Received event: {:?}", event);
            }
            Err(err) => {
                eprintln!("Error receiving event: {}", err);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {}
