use anyhow::Context;
use log::{debug, info};
use questdb::ingress::{Buffer, TimestampMicros};

use crate::ohlc::Tick;

fn flush_buffer(sender: &mut questdb::ingress::Sender, buffer: &mut Buffer) -> anyhow::Result<()> {
    debug!("Flushing to the database");
    sender
        .flush(buffer)
        .context("Failed to flush the buffer to the database")
}

pub fn ingress_regularly(
    mut sender: questdb::ingress::Sender,
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
            flush_buffer(&mut sender, &mut buffer)?;
        }
    }

    flush_buffer(&mut sender, &mut buffer)?;

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
