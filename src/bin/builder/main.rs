mod consts;
mod errors;
mod models;
mod utilities;

#[macro_use]
extern crate tracing;

use std::error::Error;

// Builder app
// Responsible of building application images; cloning repos, building and pushing images.
fn main() -> Result<(), Box<dyn Error>> {

    // TODO(benjaminch): Handle daemon mode
    let builder = models::Builder::new(models::RunningMode::OnDemand);
    //let result = builder.process()

    Ok(())
}
