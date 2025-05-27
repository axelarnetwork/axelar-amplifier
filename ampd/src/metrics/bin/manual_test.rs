use std::net::SocketAddrV4;
use std::str::FromStr;
use tokio::time::interval;

#[tokio::main]
async fn main() {
    // Create a test address (localhost:3000)
    let addr = SocketAddrV4::from_str("127.0.0.1:3000").unwrap();
    
    // Create server and client
    let (server, metrics_client) = ampd::metrics::monitor::Server::new(addr).unwrap();
    
    // Spawn the metrics server
    let cancel = tokio_util::sync::CancellationToken::new();
    tokio::spawn(server.run(cancel.clone()));

    let metrics_client_for_timer = metrics_client.clone();
    tokio::spawn(async move {
        let mut interval = interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            metrics_client_for_timer.inc_timer().unwrap();
        }
    });

    println!("Server running on http://127.0.0.1:3000");
    println!("curl http://127.0.0.1:3000/metrics");
    
    // Keep the main task running
    tokio::signal::ctrl_c().await.unwrap();
    println!("Shutting down...");
    cancel.cancel();
}