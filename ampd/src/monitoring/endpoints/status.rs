use axum::routing::{get, MethodRouter};
use axum::Json;
use serde::{Deserialize, Serialize};

/// Status response for health check endpoints
///
/// This structure represents the health status of the monitoring system
/// and is returned by the `/status` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Status {
    /// Whether the service is healthy and operational
    pub ok: bool,
}

/// Creates a status endpoint that returns health information
///
/// This endpoint always returns `{"ok": true}` to indicate that
/// the monitoring server is running and accepting requests.
///
/// # Returns
///
/// A `MethodRouter` configured to handle GET requests and return
/// a JSON status response.
pub fn create_endpoint() -> MethodRouter {
    get(Json(Status { ok: true }))
}
