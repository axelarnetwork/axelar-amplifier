use ampd_sdk::grpc::client::{new as new_client, Client};
use tokio_stream::StreamExt;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = new_client("http://127.0.0.1:9090").await?;

    println!("Connected to AMPD server at http://127.0.0.1:9090");

    let mut event_stream = client
        .subscribe(vec![], true)
        .await?;
    
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
