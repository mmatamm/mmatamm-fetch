use anyhow::Context;
use iex_parser::tops::Tops1_6Message;
use log::info;
use questdb::ingress::{Buffer, TimestampMicros};

use crate::ohlc::Tick;

pub fn ingress_regularly(
    mut sender: questdb::ingress::Sender,
    ticks: kanal::Receiver<(String, Tick)>,
    flush_threshold: usize,
) -> anyhow::Result<()> {
    let mut buffer = Buffer::new();

    // NOTE By reserving space for the buffer, we prevent re-allocation in
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

        println!("{} {:?}", &symbol, &tick);

        if buffer.len() > flush_threshold {
            info!("Flushing to the database");
            sender
                .flush(&mut buffer)
                .context("Failed to flush the buffer to the database")?;
        }
    }

    Ok(())
}

pub(crate) fn pseudo_ingress(ticks: kanal::Receiver<(String, Tick)>) -> anyhow::Result<()> {
    for (symbol, tick) in ticks {
        if &symbol == "PLTR" {
            println!("{} {:?}", &symbol, &tick);
        }
    }

    Ok(())
}
