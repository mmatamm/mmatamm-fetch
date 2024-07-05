use anyhow::{anyhow, bail, Context};
use async_compression::tokio::bufread::GzipDecoder;
use iex_parser::iex_tp::{iex_tp_segment as parse_iex_tp_segment, IexTp1Segment, IexTpSegment};
use iex_parser::message_protocol_ids;
use iex_parser::tops::{tops_1_6_message, Tops1_6Message};
use log::{error, warn};
use pcap_parser::data::PacketData;
use pcap_parser::{traits::PcapReaderIterator, PcapBlockOwned, PcapError, PcapNGReader};
use pcap_parser::{Block, Linktype};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::ipv4_checksum;
use pnet::packet::Packet;
use std::intrinsics::{likely, unlikely};
use std::io::Read;
use thiserror::Error;
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::io::SyncIoBridge;

use crate::hist::DumpMetadata;
use crate::ohlc::{self, Tick};

// TODO documents

fn extract_l2_frame(packet_data: Option<PacketData>) -> anyhow::Result<&[u8]> {
    if let Some(PacketData::L2(f)) = packet_data {
        Ok(f)
    } else {
        Err(anyhow!("Expected L2 data"))
    }
}

fn parse_ethernet_packet(frame: &[u8]) -> anyhow::Result<EthernetPacket> {
    let ethernet_packet =
        EthernetPacket::new(frame).context("Failed to parse an Ethernet packet")?;

    if likely(ethernet_packet.get_ethertype() == EtherTypes::Ipv4) {
        Ok(ethernet_packet)
    } else {
        Err(anyhow!(
            "Only IPv4 is supported, got {}",
            ethernet_packet.get_ethertype()
        ))
    }
}

fn parse_ip_packet<'a>(ethernet_packet: &'a EthernetPacket<'a>) -> anyhow::Result<Ipv4Packet<'a>> {
    let ip_packet = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload())
        .context("Failed to parse an IPv4 packet")?;

    if likely(ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp) {
        Ok(ip_packet)
    } else {
        Err(anyhow!(
            "Expected UDP, got {}",
            ip_packet.get_next_level_protocol()
        ))
    }
}

#[derive(Error, Debug)]
#[error("The UDP datagram has an unexpected checksum")]
pub struct InvalidUdpChecksum {}

fn parse_udp_datagram<'a>(packet: &'a Ipv4Packet<'a>) -> anyhow::Result<Vec<u8>> {
    let udp_datagram = &pnet::packet::udp::UdpPacket::new(packet.payload())
        .ok_or(anyhow!("Too short UDP datagram"))?;

    if udp_datagram.get_checksum()
        != ipv4_checksum(
            udp_datagram,
            &packet.get_source(),
            &packet.get_destination(),
        )
    {
        bail!(InvalidUdpChecksum {});
    }

    Ok(udp_datagram.payload().to_owned())
}

fn parse_iex_tp_1_segment(payload: &[u8]) -> anyhow::Result<IexTp1Segment> {
    let (remaining, iex_tp_segment) = parse_iex_tp_segment(payload)
        .map_err(|e| anyhow!(format!("{}", e)))
        .context("Failed to parse the IEX-TP segment")?;

    // Check there is no remaining data, which means the parser is probably outdated
    if unlikely(!remaining.is_empty()) {
        warn!(
            "There is remaining data after the IEX-TP segment: {:?}",
            &remaining
        );
    }

    let IexTpSegment::V1(iex_tp_1_segment) = iex_tp_segment;

    Ok(iex_tp_1_segment)
}

fn parse_tops_messages(segment: IexTp1Segment) -> anyhow::Result<Vec<Tops1_6Message<String>>> {
    match segment.message_protocol_id {
        message_protocol_ids::TOPS => {
            Ok(segment
                .messages
                .into_iter()
                .filter_map(|message| {
                    match tops_1_6_message(message) {
                        Ok((remaining, tops_message)) => {
                            // Check there is no remaining data, which means the parser is probably outdated
                            if !remaining.is_empty() {
                                warn!(remaining:?;
                                    "There is remaining data after the TOPS message",
                                );
                            }

                            Some(tops_message)
                        }
                        Err(e) => {
                            error!("{:#}", e);
                            None
                        }
                    }
                })
                .collect())
        }
        id => Err(anyhow!(
            "Expected TOPS message protocol ({:#04x}), got {:#04x}",
            message_protocol_ids::TOPS,
            id
        )),
    }
}

/// Parse TOPS/IEX TP/UDP/IP/Ethernet packets
fn parse_packet(packet_data: Option<PacketData>) -> anyhow::Result<Vec<Tops1_6Message<String>>> {
    let frame = extract_l2_frame(packet_data)?;

    // Parse data-link layer data
    let ethernet_packet = parse_ethernet_packet(frame)?;

    // Parse network layer data
    let ip_packet = parse_ip_packet(&ethernet_packet)?;

    // Parse transport layer data
    let udp_datagram = parse_udp_datagram(&ip_packet)?;

    // Parse IEX-TP data
    let iex_tp_1_segment = parse_iex_tp_1_segment(udp_datagram.as_slice())?;

    // Parse TOPS messages
    parse_tops_messages(iex_tp_1_segment)
}

fn parse_block(
    block: &PcapBlockOwned,
    if_linktypes: &mut Vec<Linktype>,
) -> anyhow::Result<Option<Vec<Tops1_6Message<String>>>> {
    match block {
        PcapBlockOwned::NG(a) => match a {
            // Handle packets
            Block::SimplePacket(ref b) => {
                assert!(!if_linktypes.is_empty());
                let linktype = if_linktypes[0];
                let blen = (b.block_len1 - 16) as usize;

                Ok(Some(parse_packet(pcap_parser::data::get_packetdata(
                    b.data, linktype, blen,
                ))?))
            }
            Block::EnhancedPacket(ref b) => {
                assert!((b.if_id as usize) < if_linktypes.len());
                let linktype = if_linktypes[b.if_id as usize];
                Ok(Some(parse_packet(pcap_parser::data::get_packetdata(
                    b.data,
                    linktype,
                    b.caplen as usize,
                ))?))
            }

            // Keep track of known interfaces
            Block::SectionHeader(_) => {
                if_linktypes.clear();
                Ok(None)
            }

            Block::InterfaceDescription(ref b) => {
                if_linktypes.push(b.linktype);
                Ok(None)
            }

            // Ignore other block types
            _ => Ok(None),
        },
        _ => unimplemented!(),
    }
}

pub fn for_each_block<R, F, S>(input: R, handler: F, mut state: S) -> anyhow::Result<S>
where
    R: Read,
    F: Fn(&PcapBlockOwned, &mut S) + Send + Sync + 'static,
{
    let mut pcap_reader = PcapNGReader::new(1 << 20, input)?; // TODO Move 65536 to a constant

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

    Ok(state)
}

// Process an IEX TOPS dump: download it, parse it, analyze it and upload it to the database.
pub(crate) fn for_each_tops_message<R, F, S>(
    input: R,
    handler: F,
    initial_state: S,
) -> anyhow::Result<()>
where
    R: Read,
    S: Send + Sync + 'static,
    F: Fn(&Tops1_6Message<String>, &mut S) + Send + Sync + 'static,
{
    let (_, _, _, total_packets, invalid_packets) = for_each_block(
        input,
        |block: &PcapBlockOwned,
         (owned_handler, state, if_linktypes, total_packets, invalid_packets): &mut (
            F,
            S,
            Vec<Linktype>,
            u32,
            u32,
        )| {
            *total_packets += 1;

            match parse_block(block, if_linktypes).context("Failed to parse a PCAP block") {
                Ok(Some(block)) => {
                    for message in block {
                        owned_handler(&message, state);
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    match err.downcast_ref::<InvalidUdpChecksum>() {
                        Some(InvalidUdpChecksum { .. }) => *invalid_packets += 1,
                        None => log::error!("{:#}", err),
                    };
                }
            }
        },
        (handler, initial_state, Vec::new(), 0, 0),
    )?;

    // Report statistics about the dump
    log::info!(
        // dump:? = dump;
        "{:.5}% of packets in this dump had an invalid UDP checksum",
        (invalid_packets as f32) / (total_packets as f32) * 100.0
    );

    Ok(())
}

pub(crate) fn extract_ticks<R: Read>(
    input: R,
    ticks: kanal::Sender<(String, Tick)>,
    tick_period: chrono::TimeDelta,
) -> anyhow::Result<()> {
    for_each_tops_message(
        input,
        move |message, meta_aggregator| {
            if let Tops1_6Message::QuoteUpdate(u) = message {
                if let Some(tick) = meta_aggregator.report(&u.symbol, u.ask_price, u.timestamp) {
                    ticks
                        .send((u.symbol.clone(), tick))
                        .expect("cannot send a tick through the channel");
                }
            }
        },
        ohlc::MetaAggregator::new(tick_period),
    )
}

pub(crate) async fn read_dump(
    dump: &DumpMetadata,
    ticks: kanal::Sender<(String, Tick)>,
    tick_period: chrono::TimeDelta,
) -> anyhow::Result<()> {
    // Start fetching the dump
    let response = isahc::get_async(dump.link.clone())
        .await
        .with_context(|| format!("Failed to fetch the dump from {}", dump.link))?;

    // Decompress the stream
    let compressed_data = BufReader::new(response.into_body().compat());
    let decompressed_data = GzipDecoder::new(compressed_data);

    // Parse and handle each PCAP block
    let sync_decompressed_data = SyncIoBridge::new(decompressed_data);
    tokio::task::spawn_blocking(move || extract_ticks(sync_decompressed_data, ticks, tick_period))
        .await??;

    Ok(())
}
