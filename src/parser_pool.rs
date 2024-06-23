use std::io::Read;

use anyhow::bail;
use pcap_parser::{
    traits::{PcapNGPacketBlock, PcapReaderIterator},
    Block, PcapBlockOwned, PcapError, PcapNGReader,
};
use tokio::sync::Semaphore;
use tokio_util::io::SyncIoBridge;

pub fn for_each_block<R, F, S>(input: R, handler: F, initial_state: S) -> anyhow::Result<()>
where
    R: Read,
    F: Fn(&PcapBlockOwned, &mut S) -> () + Send + Sync + 'static,
{
    let mut pcap_reader = PcapNGReader::new(1 << 20, input)?; // TODO Move 65536 to a constant

    let mut state = initial_state;

    loop {
        match pcap_reader.next() {
            // Succesfully read a block
            Ok((offset, block)) => {
                // no_blocks += 1;

                handler(&block, &mut state);

                pcap_reader.consume(offset);
            }

            // If the end oof the file is reached, break the loop
            Err(PcapError::Eof) => break,

            // On an incomplete block read, refill the buffer and continue
            Err(PcapError::Incomplete(_)) => {
                // if last_incomplete_index == no_blocks {
                //     bail!("Could not read the complete data block. The read buffer size might be too small.");
                // }

                if let Err(e) = pcap_reader.refill() {
                    bail!("{:#}", e);
                }

                continue;
            }

            // Handle other errors
            Err(e) => bail!("{:#}", e),
        }
    }

    Ok(())
}
