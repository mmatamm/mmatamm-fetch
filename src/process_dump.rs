use anyhow::{anyhow, bail, Context};
use async_compression::tokio::bufread::GzipDecoder;
use chrono::TimeDelta;
use iex_parser::iex_tp::{iex_tp_segment as parse_iex_tp_segment, IexTp1Segment, IexTpSegment};
use iex_parser::message_protocol_ids;
use iex_parser::tops::{tops_1_6_message, Tops1_6Message};
use log::warn;
use pcap_parser::data::PacketData;
use pcap_parser::{Block, Linktype, PcapBlockOwned};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::ipv4_checksum;
use pnet::packet::Packet;
use thiserror::Error;
use tokio::io::BufReader;
use tokio_util::compat::FuturesAsyncReadCompatExt as _;
use tokio_util::io::SyncIoBridge;

use crate::hist::DumpMetadata;
use crate::ohlc;
use crate::parser_pool::for_each_block;

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

    if ethernet_packet.get_ethertype() == EtherTypes::Ipv4 {
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

    if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
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
    if !remaining.is_empty() {
        warn!(
            "There is remaining data after the IEX-TP segment: {:?}",
            &remaining
        );
    }

    let IexTpSegment::V1(iex_tp_1_segment) = iex_tp_segment;

    Ok(iex_tp_1_segment)
}

fn parse_tops_messages(
    segment: IexTp1Segment,
) -> anyhow::Result<Vec<anyhow::Result<Tops1_6Message<String>>>> {
    match segment.message_protocol_id {
        message_protocol_ids::TOPS => {
            Ok(segment
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

/// Parse TOPS/IEX TP/UDP/IP/Ethernet packets
fn parse_packet(
    packet_data: Option<PacketData>,
) -> anyhow::Result<Vec<anyhow::Result<Tops1_6Message<String>>>> {
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
) -> Result<Option<Vec<Result<Tops1_6Message<String>, anyhow::Error>>>, anyhow::Error> {
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

// Process an IEX TOPS dump: download it, parse it, analyze it and upload it to the database.
pub(crate) async fn extract_tops_messages(dump: &DumpMetadata) -> anyhow::Result<()> {
    // Start fetching the dump
    let response = isahc::get_async(dump.link.clone()).await?;

    // Decompress the stream
    let compressed_data = BufReader::new(response.into_body().compat());
    let decompressed_data = GzipDecoder::new(compressed_data);

    // Parse and handle each PCAP block
    let sync_decompressed_data = SyncIoBridge::new(decompressed_data);
    let (_, _, total_packets, invalid_packets) = tokio::task::spawn_blocking(move || {
        for_each_block(
            sync_decompressed_data,
            |block: &PcapBlockOwned,
             (meta_aggregator, if_linktypes, total_packets, invalid_packets): &mut (
                ohlc::MetaAggregator,
                Vec<Linktype>,
                u32,
                u32,
            )| {
                *total_packets += 1;

                match parse_block(block, if_linktypes) {
                    Ok(Some(block)) => {
                        for m in block {
                            if let Ok(Tops1_6Message::QuoteUpdate(u)) = m {
                                if let Some(cool) =
                                    meta_aggregator.report(&u.symbol, u.ask_price, u.timestamp)
                                {
                                    if &u.symbol == "PLTR" {
                                        println!("{} {:?}", &u.symbol, cool);
                                    }
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        match err.downcast_ref::<InvalidUdpChecksum>() {
                            Some(InvalidUdpChecksum { .. }) => *invalid_packets += 1,
                            None => log::error!("Error while parsing the PCAP block: {:#}", err),
                        };
                    }
                }
            },
            (
                ohlc::MetaAggregator::new(TimeDelta::minutes(15)),
                Vec::new(),
                0,
                0,
            ),
        )
    })
    .await??;
    log::info!(
        dump:? = dump;
        "{}% of packets in this dump had an invalid UDP checksum",
        (invalid_packets as f32) / (total_packets as f32) * 100.0
    );

    Ok(())
}
