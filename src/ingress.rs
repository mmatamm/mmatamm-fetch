use std::sync::{Arc, Mutex};

use anyhow::Context;
use iex_parser::tops::{SystemEvent, SystemEventType};
use log::{debug, info};
use questdb::ingress::{Buffer, TimestampMicros};

use crate::{data_targets::DataTargets, ohlc::Tick};

fn flush_buffer(
    sender_mut: &Arc<Mutex<questdb::ingress::Sender>>,
    buffer: &mut Buffer,
) -> anyhow::Result<()> {
    debug!("Flushing to the database");

    let mut sender = sender_mut.lock().unwrap();
    sender
        .flush(buffer)
        .context("Failed to flush the buffer to the database")
}

fn ingress_prices_regularly(
    sender: Arc<Mutex<questdb::ingress::Sender>>,
    ticks: kanal::Receiver<(String, Tick)>,
    flush_threshold: usize,
) -> anyhow::Result<()> {
    let mut buffer = Buffer::new();

    // By reserving space for the buffer, we prevent re-allocation in
    // the first round _almost_ completely
    buffer.reserve(flush_threshold);

    for (symbol, tick) in ticks {
        buffer
            .table("ticks")?
            .symbol("symbol", &symbol)?
            .column_f64("open", tick.open)?
            .column_f64("high", tick.high)?
            .column_f64("low", tick.low)?
            .column_f64("close", tick.close)?
            .at(TimestampMicros::from_datetime(tick.timestamp))?;

        if buffer.len() > flush_threshold {
            flush_buffer(&sender, &mut buffer)?;
        }
    }

    flush_buffer(&sender, &mut buffer)?;

    Ok(())
}

fn ingress_events_regularly(
    sender: Arc<Mutex<questdb::ingress::Sender>>,
    events: kanal::Receiver<SystemEvent>,
    flush_threshold: usize,
) -> anyhow::Result<()> {
    let mut buffer = Buffer::new();

    // By reserving space for the buffer, we prevent re-allocation in
    // the first round _almost_ completely
    buffer.reserve(flush_threshold);

    for event in events {
        let event_symbol_opt = match event.event_type {
            iex_parser::tops::SystemEventType::StartOfSystemHours => Some("system_hours_start"),
            iex_parser::tops::SystemEventType::StartOfRegularHours => Some("regular_hours_start"),
            iex_parser::tops::SystemEventType::EndOfRegularHours => Some("regular_hours_end"),
            iex_parser::tops::SystemEventType::EndOfSystemHours => Some("system_hours_end"),
            _ => None,
        };

        if let Some(event_symbol) = event_symbol_opt {
            buffer
                .table("system_events")?
                .symbol("type", event_symbol)?
                .at(TimestampMicros::from_datetime(event.timestamp))?;

            if buffer.len() > flush_threshold {
                flush_buffer(&sender, &mut buffer)?;
            }
        }
    }

    flush_buffer(&sender, &mut buffer)?;

    Ok(())
}

pub async fn ingress_regularly(
    sender: questdb::ingress::Sender,
    ticks: kanal::Receiver<(String, Tick)>,
    events: kanal::Receiver<SystemEvent>,
    flush_threshold: usize,
    targets: DataTargets,
) -> anyhow::Result<()> {
    let sender_mut = Arc::new(Mutex::new(sender));

    if targets.trade_prices {
        let sender_clone = Arc::clone(&sender_mut);

        tokio::task::spawn_blocking(move || {
            ingress_prices_regularly(sender_clone, ticks, flush_threshold)
        });
    }

    if targets.system_events {
        let sender_clone = Arc::clone(&sender_mut);

        tokio::task::spawn_blocking(move || {
            ingress_events_regularly(sender_clone, events, flush_threshold)
        });
    }

    Ok(())
}

pub(crate) fn pseudo_ingress(ticks: kanal::Receiver<(String, Tick)>) -> anyhow::Result<()> {
    let mut total = 0;

    for (symbol, tick) in ticks {
        total += 1;

        if total % 100_000 == 0 {
            info!("Processed {} ticks", total);
        }
        // if &symbol == "PLTR" {
        //     println!("{} {:?}", &symbol, &tick);
        // }
    }

    Ok(())
}
