//! Monitoring module for ampd
//!
//! This module provides monitoring capabilities including metrics collection,
//! HTTP endpoints for health checks and metrics exposure, and a configurable
//! monitoring server that can be enabled or disabled.
//!
//! # Features
//!
//! - **Metrics Collection**: Collects and exposes Prometheus-compatible metrics
//! - **Health Endpoints**: Provides status endpoints for health checks
//! - **Configurable Server**: Can be enabled/disabled via configuration
//! - **Graceful Shutdown**: Handles cancellation tokens for clean shutdown

mod endpoints;
mod server;
pub use endpoints::metrics;
pub use server::*;
