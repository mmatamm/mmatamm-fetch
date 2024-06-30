use crate::ohlc::Tick;

pub(crate) fn pseudo_ingress(ticks: kanal::Receiver<(String, Tick)>) -> anyhow::Result<()> {
    for (symbol, tick) in ticks {
        if &symbol == "PLTR" {
            println!("{} {:?}", &symbol, &tick);
        }
    }

    Ok(())
}
