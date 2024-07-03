#![feature(async_closure)]
#![feature(map_try_insert)]
#![feature(assert_matches)]

mod concurrent_for_each;
mod hist;
mod ingress;
mod ohlc;
mod process_dump;

use std::error::Error;

use anyhow::Context;
use chrono::NaiveDate;
use clap::Parser;
use concurrent_for_each::concurrent_for_each;
use flexi_logger::Logger;
use hist::DumpMetadata;
use ingress::{ingress_regularly, pseudo_ingress};
use isahc::AsyncReadResponseExt;
use log::error;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The first day to add to the server
    #[arg(long)]
    from: Option<NaiveDate>,

    /// The last day to add to the server
    #[arg(long)]
    until: Option<NaiveDate>,

    /// The URL of the IEX API 'hist' file
    #[arg(long, default_value = hist::URL)]
    hist: String,

    /// The amount of workers for fetching and parsing
    #[arg(long, default_value_t = 4)]
    workers: u8,
}

/// Checks if a dump file should be processed based on the provided arguments.
///
/// # Arguments
/// * `args` - The command line arguments, as parsed by clap::Parser.
/// * `dump` - The metadata of the dump file to process.
///
/// # Returns
/// Whether or not the given dump file should be processed based on the provided arguments.
fn filter_dump(args: &Args, dump: &DumpMetadata) -> bool {
    let from_limit = if let Some(from) = args.from {
        dump.date >= from
    } else {
        true
    };

    let until_limit = if let Some(until) = args.until {
        dump.date <= until
    } else {
        true
    };

    let is_tops = dump.feed == "TOPS";

    assert_eq!(dump.protocol, "IEXTP1");

    let delme_condition = dump.version == "1.6"; // TODO delme!

    from_limit && until_limit && is_tops && delme_condition
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    // Start the logger
    Logger::try_with_env_or_str("info")?.start()?;

    // Parse CLI argumetns
    let args = Args::parse();

    // Fetch the hist.json using IEX's API
    log::debug!("Fetching dumps list from {}", &args.hist);
    let all_dumps: hist::Hist = isahc::get_async(&args.hist)
        .await
        .context("Failed to fetch the dumps list")?
        .json()
        .await
        .context("Failed to parse the dumps list")?;

    // Filter the dumps we're not interested in
    // TODO use iter::filter_map, maybe, think about async
    let relevant_dumps: Vec<_> = all_dumps
        .0
        .values()
        .flatten()
        .filter(|dump| filter_dump(&args, dump))
        .collect();

    let (ticks_sender, ticks_receiver) = kanal::bounded(1000);

    let sender = questdb::ingress::Sender::from_conf("http::addr=localhost:9000;")?;
    // tokio::task::spawn_blocking(move || ingress_regularly(sender, ticks_receiver, 10000));
    tokio::task::spawn_blocking(move || pseudo_ingress(ticks_receiver));

    // BUG This caused the compiler to ICE. It is fixed in version 1.8.1.
    concurrent_for_each(
        |dump| {
            let value = ticks_sender.clone();
            async move {
                if let Err(err) = process_dump::read_dump(dump, value).await {
                    error!(dump:?; "{:#}", err);
                }
            }
        },
        relevant_dumps,
        args.workers,
    )
    .await?;

    Ok(())
}
