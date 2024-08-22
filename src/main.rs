#![feature(async_closure)]
#![feature(map_try_insert)]
#![feature(assert_matches)]
#![feature(core_intrinsics)]
#![feature(duration_constructors)]

mod concurrent_for_each;
mod data_targets;
mod hist;
mod ingress;
mod ohlc;
mod process_dump;

use std::{intrinsics::unlikely, path::PathBuf, time::Duration};

use anyhow::{bail, Context};
use chrono::{NaiveDate, TimeDelta};
use clap::{ArgAction, Parser};
use concurrent_for_each::concurrent_for_each;
use data_targets::DataTargets;
use flexi_logger::{colored_detailed_format, json_format, FileSpec, LogSpecification, Logger};
use hist::DumpMetadata;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
use ingress::{ingress_regularly, pseudo_ingress};
use isahc::AsyncReadResponseExt;
use log::{error, info, warn};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// The first day to add to the server
    #[arg(long)]
    from: Option<NaiveDate>,

    /// The last day to add to the server
    #[arg(long)]
    until: Option<NaiveDate>,

    ///  The length of each OHLC tick
    #[arg(short, long, default_value = "1 min")]
    tick_period: humantime::Duration,

    /// The URL of the IEX API 'hist' file
    #[arg(long, default_value = hist::URL)]
    hist: String,

    /// The amount of workers for fetching and parsing
    #[arg(long, default_value_t = 4)]
    workers: u8,

    /// The directory to store the logs in. The default is the current working directory.
    #[arg(long)]
    logs: Option<PathBuf>,

    /// After aggregating this amount of bytes, flush them to the database
    #[arg(long, default_value_t = 10_000)]
    flush_threshold: usize,

    /// Do not compute and upload OHLC ticks of trade prices
    #[arg(long = "no-trade-prices", action=ArgAction::SetFalse)]
    upload_trade_prices: bool,

    /// Do not upload system events (e.g. regular hours start/end) to a dedicated table
    #[arg(long = "no-system-events", action=ArgAction::SetFalse)]
    upload_system_events: bool,
}

/// Checks if a dump file should be processed based on the provided arguments.
///
/// # Arguments
/// * `args` - The command line arguments, as parsed by clap::Parser.
/// * `dump` - The metadata of the dump file to process.
///
/// # Returns
/// Whether or not the given dump file should be processed based on the provided arguments.
fn filter_dump(dump: &DumpMetadata, from: Option<NaiveDate>, until: Option<NaiveDate>) -> bool {
    let from_limit = if let Some(from) = from {
        dump.date >= from
    } else {
        true
    };

    let until_limit = if let Some(until) = until {
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
async fn main() -> anyhow::Result<()> {
    // Parse CLI argumetns
    let args = Args::parse();

    if unlikely(Duration::from_days(1) < args.tick_period.into()) {
        bail!("A tick cannot be longer than a day");
    }

    // Start the logger and ensure it doesn't interfere with progress bars
    let (boxed_logger, _logger_handle) = Logger::with(LogSpecification::info())
        .format_for_files(json_format)
        .log_to_file(FileSpec::default().o_directory(args.logs))
        .format_for_stderr(colored_detailed_format)
        .print_message()
        .duplicate_to_stderr(flexi_logger::Duplicate::Warn)
        .build()?;
    let progress_bars = MultiProgress::new();
    LogWrapper::new(progress_bars.clone(), boxed_logger).try_init()?;

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
        .filter(|dump| filter_dump(dump, args.from, args.until))
        .collect();

    // FIX 1000 is a magic number!
    let (ticks_sender, ticks_receiver) = kanal::bounded(1000);
    let (events_sender, events_receiver) = kanal::bounded(1000);

    let sender = {
        let result = questdb::ingress::Sender::from_env();

        if result.is_err() {
            warn!("You might need to set an environment variable 'QDB_CLIENT_CONF' with the QuestDB server address. For example, `export QDB_CLIENT_CONF=\"http::addr=localhost:9009;\"`.")
        }

        result
    }?;

    let targets = DataTargets {
        trade_prices: args.upload_trade_prices,
        system_events: args.upload_system_events,
    };
    info!("Uploading the following data targets: {:#?}", targets);

    // tokio::task::spawn_blocking(move || {
    //     ingress_regularly(sender, ticks_receiver, events_receiver, 10000, targets)
    // });
    ingress_regularly(sender, ticks_receiver, events_receiver, 10000, targets).await?;
    // tokio::task::spawn_blocking(move || pseudo_ingress(ticks_receiver));

    // Create a sexy progress bar
    let total_progress = progress_bars.add(
        ProgressBar::new(relevant_dumps.len() as u64)
            .with_prefix("Processing IEX dumps")
            .with_style(
                ProgressStyle::default_bar()
                    .template("{prefix}: {wide_bar} {human_pos}/{human_len}, Elapsed: {elapsed}")
                    .unwrap(),
            ),
    );
    total_progress.enable_steady_tick(Duration::from_secs(10));

    // BUG This caused the compiler to ICE. It is fixed in version 1.8.1.
    concurrent_for_each(
        |dump| {
            let local_ticks_sender = ticks_sender.clone();
            let local_events_sender = events_sender.clone();
            let local_progress_bar = total_progress.clone();

            async move {
                if let Err(err) = process_dump::read_dump(
                    dump,
                    local_ticks_sender,
                    local_events_sender,
                    TimeDelta::from_std(args.tick_period.into()).unwrap(),
                    targets,
                )
                .await
                {
                    error!(dump:?; "{:#}", err);
                }

                local_progress_bar.inc(1);
            }
        },
        relevant_dumps,
        args.workers,
    )
    .await?;

    total_progress.finish();
    progress_bars.remove(&total_progress);

    Ok(())
}
