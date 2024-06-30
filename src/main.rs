#![feature(async_closure)]
#![feature(map_try_insert)]

mod hist;
mod ingress;
mod join_n_at_a_time;
mod ohlc;
mod process_dump;

use std::error::Error;

use anyhow::Context;
use chrono::NaiveDate;
use clap::Parser;
use flexi_logger::Logger;
use hist::DumpMetadata;
use ingress::pseudo_ingress;
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
    let relevant_dumps = all_dumps
        .0
        .values()
        .flatten()
        .filter(|dump| filter_dump(&args, dump));

    let (ticks_sender, ticks_receiver) = kanal::bounded(1000);

    tokio::task::spawn_blocking(move || pseudo_ingress(ticks_receiver));

    let dump = relevant_dumps.last().unwrap();
    if let Err(err) = process_dump::read_dump(dump, ticks_sender.clone()).await {
        error!(dump:?; "{:#}", err);
    }

    // TODO Consider limiting the amount of handled requests per moment
    // BUG This causes the compiler to ICE. It should be fixed by this PR: https://github.com/rust-lang/rust/pull/127136
    // join_n_at_a_time::join_n_at_a_time(relevant_dumps.map(async |dump| {
    //     if let Err(err) = process_dump::read_dump(dump, ticks_sender.clone()).await {
    //         error!(dump:?; "{:#}", err);
    //     }
    // }))
    // .await;

    Ok(())
}
