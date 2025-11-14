use tracing::Level;
use tracing_core::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub fn init_tracing(max_level: Level) {
    let error_layer = ErrorLayer::default();
    let filter_layer = EnvFilter::builder()
        .with_default_directive(LevelFilter::from_level(max_level).into())
        .from_env_lossy();
    let fmt_layer = tracing_subscriber::fmt::layer().json().flatten_event(true);

    tracing_subscriber::registry()
        .with(error_layer)
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}
