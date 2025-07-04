//! HTTP endpoints for the monitoring server
//!
//! This module contains the implementation of HTTP endpoints served by the monitoring server:
//!
//! - **metrics**: Prometheus-compatible metrics endpoint for observability
//! - **status**: Health check endpoint for service monitoring

pub mod metrics;
pub mod status;
