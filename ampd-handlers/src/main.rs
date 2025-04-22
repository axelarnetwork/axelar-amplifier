use ampd_sdk::grpc::client;
use tokio_util::sync::CancellationToken;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut _grpc_client = client::new("http://localhost:50051").await?;
    // let handler = EventHandlerImpl::new(...);
    let _token = CancellationToken::new();
    // HandlerTask::new(client, handler).run(token).await;

    Ok(())
}

#[cfg(test)]
mod tests {}
