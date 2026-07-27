//! Synthetic packet builders. Available to tests only.
//!
//! Built with smoltcp's own setters rather than hand-written bytes, so
//! checksums are always correct and the tests exercise real parsing.

use std::net::Ipv4Addr;

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber, UdpPacket};

#[derive(Clone, Copy, Default, Debug)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    pub fn syn() -> Self {
        Self {
            syn: true,
            ..Default::default()
        }
    }
    pub fn ack() -> Self {
        Self {
            ack: true,
            ..Default::default()
        }
    }
    // Not consumed until a later packet-engine task tests teardown segments;
    // kept here now because every such test shares this builder module.
    #[allow(dead_code)]
    pub fn fin_ack() -> Self {
        Self {
            fin: true,
            ack: true,
            ..Default::default()
        }
    }
}

fn ipv4_frame(src: Ipv4Addr, dst: Ipv4Addr, proto: IpProtocol, payload_len: usize) -> Vec<u8> {
    let total = 20 + payload_len;
    let mut buf = vec![0u8; total];
    let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
    ip.set_version(4);
    ip.set_header_len(20);
    ip.set_total_len(total as u16);
    ip.set_ident(0);
    ip.set_dont_frag(true);
    ip.set_more_frags(false);
    ip.set_frag_offset(0);
    ip.set_hop_limit(64);
    ip.set_next_header(proto);
    ip.set_src_addr(src);
    ip.set_dst_addr(dst);
    buf
}

pub fn build_tcp(
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
    flags: TcpFlags,
    seq: u32,
    ack: u32,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let mut buf = ipv4_frame(src.0, dst.0, IpProtocol::Tcp, tcp_len);
    {
        let mut tcp = TcpPacket::new_unchecked(&mut buf[20..]);
        tcp.set_src_port(src.1);
        tcp.set_dst_port(dst.1);
        tcp.set_seq_number(TcpSeqNumber(seq as i32));
        tcp.set_ack_number(TcpSeqNumber(ack as i32));
        tcp.set_header_len(20);
        tcp.set_syn(flags.syn);
        tcp.set_ack(flags.ack);
        tcp.set_fin(flags.fin);
        tcp.set_rst(flags.rst);
        tcp.set_window_len(65535);
        tcp.payload_mut().copy_from_slice(payload);
        tcp.fill_checksum(&IpAddress::Ipv4(src.0), &IpAddress::Ipv4(dst.0));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    buf
}

pub fn build_udp(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut buf = ipv4_frame(src.0, dst.0, IpProtocol::Udp, udp_len);
    {
        let mut udp = UdpPacket::new_unchecked(&mut buf[20..]);
        udp.set_src_port(src.1);
        udp.set_dst_port(dst.1);
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.fill_checksum(&IpAddress::Ipv4(src.0), &IpAddress::Ipv4(dst.0));
    }
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut buf[..]);
        ip.fill_checksum();
    }
    buf
}
