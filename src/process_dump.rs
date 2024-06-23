use anyhow::{anyhow, bail, Context};
use async_compression::tokio::bufread::GzipDecoder;
use chrono::TimeDelta;
use iex_parser::iex_tp::{iex_tp_segment as parse_iex_tp_segment, IexTpSegment};
use iex_parser::message_protocol_ids;
use iex_parser::tops::{tops_1_6_message, Tops1_6Message};
use log::warn;
use pcap_parser::data::PacketData;
use pcap_parser::{Block, Linktype, PcapBlockOwned};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::io::SyncIoBridge;

use crate::hist::DumpMetadata;
use crate::ohlc;
use crate::parser_pool::for_each_block;

// TODO documents

/// Parse TOPS/IEX TP/UDP/IP/Ethernet packets
fn parse_packet(
    packet_data: Option<PacketData>,
) -> anyhow::Result<Vec<anyhow::Result<Tops1_6Message<String>>>> {
    let frame = if let Some(PacketData::L2(f)) = packet_data {
        f
    } else {
        bail!("Expected L2 data");
    };

    // Parse data-link layer data
    let ethernet_packet =
        EthernetPacket::new(&frame).context("Failed to parse an Ethernet packet")?;

    if ethernet_packet.get_ethertype() != EtherTypes::Ipv4 {
        bail!(
            "Only IPv4 is supported, got {}",
            ethernet_packet.get_ethertype()
        );
    }

    // Parse network layer data
    let ip_packet = pnet::packet::ipv4::Ipv4Packet::new(ethernet_packet.payload())
        .context("Failed to parse an IPv4 packet")?;

    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
        bail!("Expected UDP, got {}", ip_packet.get_next_level_protocol());
    }

    // Parse transport layer data
    let udp_datagram = pnet::packet::udp::UdpPacket::new(ip_packet.payload()).unwrap();
    // println!("{}", simple_hex(&udp_datagram.payload()));

    // TODO verify checksums

    // Parse IEX-TP data
    let (remaining, iex_tp_segment) = parse_iex_tp_segment(&udp_datagram.payload())
        .map_err(|e| anyhow!(format!("{}", e)))
        .context("Failed to parse the IEX-TP segment")?;

    // Check there is no remaining data, which means the parser is probably outdated
    if !remaining.is_empty() {
        warn!(
            "There is remaining data after the IEX-TP segment: {:?}",
            &remaining
        );
    }

    let IexTpSegment::V1(iex_tp_1_segment) = iex_tp_segment;

    // Parse TOPS messages
    match iex_tp_1_segment.message_protocol_id {
        message_protocol_ids::TOPS => {
            Ok(iex_tp_1_segment
                .messages
                .into_iter()
                .map(|message| {
                    let (remaining, tops_message) =
                        tops_1_6_message(message).map_err(|e| anyhow!(format!("{}", e)))?;

                    // Check there is no remaining data, which means the parser is probably outdated
                    if !remaining.is_empty() {
                        warn!(remaining:?;
                            "There is remaining data after the TOPS message",
                        );
                    }

                    Ok(tops_message)
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

fn parse_block(
    block: &PcapBlockOwned,
    if_linktypes: &mut Vec<Linktype>,
) -> Result<Option<Vec<Result<Tops1_6Message<String>, anyhow::Error>>>, anyhow::Error> {
    match block {
        PcapBlockOwned::NG(a) => match a {
            // Handle packets
            Block::SimplePacket(ref b) => {
                assert!(if_linktypes.len() > 0);
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

// Process an IEX TOPS dump: download it, parse it, analyze it and upload it to the database.
pub(crate) async fn extract_tops_messages(dump: &DumpMetadata) -> anyhow::Result<()> {
    // Start fetching the dump
    log::info!("Fetching dump ({}) from {}", dump.date, dump.link);
    let response = isahc::get_async(dump.link.clone()).await?;

    // Decompress the stream
    let compressed_data = BufReader::new(response.into_body().compat());
    let decompressed_data = GzipDecoder::new(compressed_data);

    // Parse and handle each PCAP block
    let sync_decompressed_data = SyncIoBridge::new(decompressed_data);
    tokio::task::spawn_blocking(move || {
        for_each_block(
            sync_decompressed_data,
            |block: &PcapBlockOwned,
             (meta_aggregator, if_linktypes): &mut (ohlc::MetaAggregator, Vec<Linktype>)| {
                match parse_block(block, if_linktypes) {
                    Ok(Some(block)) => {
                        for m in block {
                            if let Ok(Tops1_6Message::QuoteUpdate(u)) = m {
                                if let Some(cool) = meta_aggregator.report(&u.symbol, u.ask_price, u.timestamp) {
                                    if &u.symbol == "PLTR" {
                                        println!(
                                            "{} {:?}", &u.symbol, cool
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        log::error!("Error while parsing the PCAP block: {:#}", err);
                    }
                }
            },
            (ohlc::MetaAggregator::new(TimeDelta::minutes(15)), Vec::new()),
        )
    })
    .await??;

    Ok(())
}
