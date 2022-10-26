//! This is a plugin which adds a "hodlinvoice" 
//! command to Core Lightning.
#[macro_use]
extern crate serde_json;
use cln_plugin::{Builder, Error, Plugin};
use tokio;
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let state = ();

    if let Some(plugin) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .rpcmethod("hodlinvoice", 
                   "Call this to create an invoice that will be held until released", 
                   hodlmethod)
        .hook("htlc_accepted", htlc_accept_handler)
        .start(state)
        .await?
    {
        plugin.join().await
    } else {
        Ok(())
    }
}

//! TODO: what info do we need to pass into hodlinvoice?
//! TODO: what should we do with this information?
//! nifty guesses: 
//!     - create an invoice, and remember the preimage/hash
//!     - when an htlc with that same preimage/hash is 
//!     notified in htlc_accept_handler, hold the invoice!
//!     - when do we release the invoice??
async fn hodlmethod(_p: Plugin<()>, _v: serde_json::Value) -> Result<serde_json::Value, Error> {
    Ok(json!("Hello"))
}

async fn htlc_accept_handler(
    _p: Plugin<()>,
    v: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    log::info!("Got a htlc accepted call: {}", v);
    Ok(json!({"result": "continue"}))
}
