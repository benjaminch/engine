mod consts;
mod errors;
mod models;
mod utilities;

#[macro_use]
extern crate tracing;

use qovery_engine::container_registry::{Kind};
use std::error::Error;
use tracing_subscriber::{
    fmt::{format, time::ChronoUtc},
    prelude::*,
    EnvFilter,
};

// Builder app
// Responsible of building application images; cloning repos, building and pushing images.
fn main() -> Result<(), Box<dyn Error>> {
    // Init tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .fmt_fields(
            tracing_subscriber::fmt::format::debug_fn(|writer, field, value| write!(writer, "{}: {:?}", field, value))
                .delimited(", "),
        )
        .with_ansi(false)
        .with_timer(ChronoUtc::with_format("%Y-%m-%dT%H:%M:%SZ".to_string()))
        .init();

    // TODO(benjaminch): Handle daemon mode, might fire a tokyio task for each new request in daemon mode
    let builder = models::Builder::new(models::RunningMode::OnDemand);

    let result = builder.process(
        "application_id".into(),
        false,
        "execution_id".into(),
        "/tmp/qovery-test".into(),
        "repo".into(),
        "https://github.com/prebid/prebid-server.git".into(),
        "ccb56efe1f23ee101aef3fc604db799a1282f7f9".into(),
        None,
        vec![],
        vec![],
        None,
        Some("Dockerfile".into()),
        "prebid-server".into(),
        "yolo".into(),
        Kind::DockerHub,
        None,
        None,
        None,
    );

    Ok(())
}
