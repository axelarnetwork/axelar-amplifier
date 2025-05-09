use std::env;

use ampd_sdk::grpc::client::{new as new_client, Client};
use tokio_stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ampd_url =
        env::var("AMPD_SERVICE_URL").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());

    println!("Attempting to connect to AMPD server at {}", ampd_url);
    let mut client = new_client(&ampd_url).await?;

    println!("Connected to AMPD server at {}", ampd_url);

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
