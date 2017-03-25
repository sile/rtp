use std::io::{Read, Write};
use handy_async::sync_io::{ReadExt, WriteExt};

use {Result, ErrorKind};
use io::{ReadFrom, WriteTo};
use packet::Packet;
use types::{U5, U24, RtpTimestamp, NtpTimestamp, NtpMiddleTimetamp, Ssrc, SsrcOrCsrc};
use constants::RTP_VERSION;

pub const RTCP_PACKET_TYPE_SR: u8 = 200;
pub const RTCP_PACKET_TYPE_RR: u8 = 201;
pub const RTCP_PACKET_TYPE_SDES: u8 = 202;
pub const RTCP_PACKET_TYPE_BYE: u8 = 203;
pub const RTCP_PACKET_TYPE_APP: u8 = 204;

pub const SDES_ITEM_TYPE_END: u8 = 0;
pub const SDES_ITEM_TYPE_CNAME: u8 = 1;
pub const SDES_ITEM_TYPE_NAME: u8 = 2;
pub const SDES_ITEM_TYPE_EMAIL: u8 = 3;
pub const SDES_ITEM_TYPE_PHONE: u8 = 4;
pub const SDES_ITEM_TYPE_LOC: u8 = 5;
pub const SDES_ITEM_TYPE_TOOL: u8 = 6;
pub const SDES_ITEM_TYPE_NOTE: u8 = 7;
pub const SDES_ITEM_TYPE_PRIV: u8 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    Sr(RtcpSenderReport),
    Rr(RtcpReceiverReport),
    Sdes(RtcpSourceDescription),
    Bye(RtcpGoodbye),
    App(RtcpApplicationDefined),
}
impl Packet for RtcpPacket {}
impl ReadFrom for RtcpPacket {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0; 2];
        track_try!(reader.read_exact(&mut buf));

        let reader = &mut (&buf[..]).chain(reader);
        let packet_type = buf[1];
        match packet_type {
            RTCP_PACKET_TYPE_SR => track_err!(RtcpSenderReport::read_from(reader).map(From::from)),
            RTCP_PACKET_TYPE_RR => {
                track_err!(RtcpReceiverReport::read_from(reader).map(From::from))
            }
            RTCP_PACKET_TYPE_SDES => {
                track_err!(RtcpSourceDescription::read_from(reader).map(From::from))
            }
            RTCP_PACKET_TYPE_BYE => track_err!(RtcpGoodbye::read_from(reader).map(From::from)),
            RTCP_PACKET_TYPE_APP => {
                track_err!(RtcpApplicationDefined::read_from(reader).map(From::from))
            }
            _ => {
                track_panic!(ErrorKind::Unsupported,
                             "Unknown packet type: {}",
                             packet_type)
            }
        }
    }
}
impl WriteTo for RtcpPacket {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            RtcpPacket::Sr(ref p) => track_err!(p.write_to(writer)),
            RtcpPacket::Rr(ref p) => track_err!(p.write_to(writer)),
            RtcpPacket::Sdes(ref p) => track_err!(p.write_to(writer)),
            RtcpPacket::Bye(ref p) => track_err!(p.write_to(writer)),
            RtcpPacket::App(ref p) => track_err!(p.write_to(writer)),
        }
    }
}
impl From<RtcpSenderReport> for RtcpPacket {
    fn from(f: RtcpSenderReport) -> Self {
        RtcpPacket::Sr(f)
    }
}
impl From<RtcpReceiverReport> for RtcpPacket {
    fn from(f: RtcpReceiverReport) -> Self {
        RtcpPacket::Rr(f)
    }
}
impl From<RtcpSourceDescription> for RtcpPacket {
    fn from(f: RtcpSourceDescription) -> Self {
        RtcpPacket::Sdes(f)
    }
}
impl From<RtcpGoodbye> for RtcpPacket {
    fn from(f: RtcpGoodbye) -> Self {
        RtcpPacket::Bye(f)
    }
}
impl From<RtcpApplicationDefined> for RtcpPacket {
    fn from(f: RtcpApplicationDefined) -> Self {
        RtcpPacket::App(f)
    }
}

fn read_sctp<R: Read>(reader: &mut R, expected_type: u8) -> Result<(U5, Vec<u8>)> {
    let b = track_try!(reader.read_u8());
    track_assert_eq!(b >> 6,
                     RTP_VERSION,
                     ErrorKind::Unsupported,
                     "Unsupported RTP version: {}",
                     b >> 6);
    let padding = (b & 0b0010_0000) != 0;
    let packet_specific = b & 0b0001_1111;

    let packet_type = track_try!(reader.read_u8());
    track_assert_eq!(packet_type,
                     expected_type,
                     ErrorKind::Invalid,
                     "Unexpected SCTP packet type: actual={}, expected={}",
                     packet_type,
                     expected_type);

    let word_count = track_try!(reader.read_u16be()) as usize;
    let mut payload = track_try!(reader.read_bytes(word_count * 4));
    if padding {
        let payload_len = payload.len();
        track_assert_ne!(payload_len, 0, ErrorKind::Invalid);

        let padding_len = payload[payload_len - 1] as usize;
        track_assert!(padding_len <= payload.len(), ErrorKind::Invalid);

        payload.truncate(payload_len - padding_len);
    }
    track_assert_eq!(payload.len() % 4, 0, ErrorKind::Invalid);

    Ok((packet_specific, payload))
}

fn write_sctp<W: Write>(writer: &mut W,
                        packet_type: u8,
                        packet_specific: U5,
                        payload: &[u8])
                        -> Result<()> {
    track_assert_eq!(payload.len() % 4, 0, ErrorKind::Invalid);

    track_try!(writer.write_u8(RTP_VERSION << 6 | packet_specific));
    track_try!(writer.write_u8(packet_type));

    let word_count = payload.len() / 4;
    track_assert!(word_count < 0x10000, ErrorKind::Invalid);

    track_try!(writer.write_u16be(word_count as u16));
    track_try!(writer.write_all(payload));

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSenderReport {
    pub ssrc: Ssrc,
    pub ntp_timestamp: NtpTimestamp,
    pub rtp_timestamp: RtpTimestamp,
    pub sent_packets: u32,
    pub sent_octets: u32,
    pub reception_reports: Vec<ReceptionReport>,
    pub extensions: Vec<u8>,
}
impl RtcpSenderReport {
    pub fn new(ssrc: Ssrc) -> Self {
        RtcpSenderReport {
            ssrc: ssrc,
            ntp_timestamp: 0,
            rtp_timestamp: 0,
            sent_packets: 0,
            sent_octets: 0,
            reception_reports: Vec::new(),
            extensions: Vec::new(),
        }
    }
}
impl ReadFrom for RtcpSenderReport {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (reception_report_count, payload) = track_try!(read_sctp(reader, RTCP_PACKET_TYPE_SR));
        let reader = &mut &payload[..];

        let ssrc = track_try!(reader.read_u32be());

        let ntp_timestamp = track_try!(reader.read_u64be());
        let rtp_timestamp = track_try!(reader.read_u32be());
        let sent_packets = track_try!(reader.read_u32be());
        let sent_octets = track_try!(reader.read_u32be());

        let mut reception_reports = Vec::new();
        for _ in 0..reception_report_count {
            let report = track_try!(ReceptionReport::read_from(reader));
            reception_reports.push(report);
        }
        let extensions = track_try!(reader.read_all_bytes());

        Ok(RtcpSenderReport {
               ssrc: ssrc,
               ntp_timestamp: ntp_timestamp,
               rtp_timestamp: rtp_timestamp,
               sent_packets: sent_packets,
               sent_octets: sent_octets,
               reception_reports: reception_reports,
               extensions: extensions,
           })
    }
}
impl WriteTo for RtcpSenderReport {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut payload = Vec::new();
        track_try!((&mut payload).write_u32be(self.ssrc));
        track_try!((&mut payload).write_u64be(self.ntp_timestamp));
        track_try!((&mut payload).write_u32be(self.rtp_timestamp));
        track_try!((&mut payload).write_u32be(self.sent_packets));
        track_try!((&mut payload).write_u32be(self.sent_octets));
        for report in self.reception_reports.iter() {
            track_try!(report.write_to(&mut payload));
        }
        payload.extend(&self.extensions);

        track_assert!(self.reception_reports.len() <= 0x0001_1111,
                      ErrorKind::Invalid);
        track_try!(write_sctp(writer,
                              RTCP_PACKET_TYPE_SR,
                              self.reception_reports.len() as u8,
                              &payload));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceptionReport {
    pub ssrc: Ssrc,
    pub fraction_lost: u8,
    pub packets_lost: U24,
    pub seq_num_ext: u32,
    pub jitter: u32,
    pub last_sr_timestamp: NtpMiddleTimetamp,
    pub delay_since_last_sr: u32,
}
impl ReceptionReport {
    pub fn new(ssrc: Ssrc) -> Self {
        ReceptionReport {
            ssrc: ssrc,
            fraction_lost: 0,
            packets_lost: 0,
            seq_num_ext: 0,
            jitter: 0,
            last_sr_timestamp: 0,
            delay_since_last_sr: 0,
        }
    }
}
impl ReadFrom for ReceptionReport {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let ssrc = track_try!(reader.read_u32be());
        let fraction_lost = track_try!(reader.read_u8());
        let packets_lost = track_try!(reader.read_u24be());
        let seq_num_ext = track_try!(reader.read_u32be());
        let jitter = track_try!(reader.read_u32be());
        let last_sr_timestamp = track_try!(reader.read_u32be());
        let delay_since_last_sr = track_try!(reader.read_u32be());

        Ok(ReceptionReport {
               ssrc: ssrc,
               fraction_lost: fraction_lost,
               packets_lost: packets_lost,
               seq_num_ext: seq_num_ext,
               jitter: jitter,
               last_sr_timestamp: last_sr_timestamp,
               delay_since_last_sr: delay_since_last_sr,
           })
    }
}
impl WriteTo for ReceptionReport {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_assert!(self.packets_lost <= 0x00FF_FFFF, ErrorKind::Invalid);

        track_try!(writer.write_u32be(self.ssrc));
        track_try!(writer.write_u8(self.fraction_lost));
        track_try!(writer.write_u24be(self.packets_lost));
        track_try!(writer.write_u32be(self.seq_num_ext));
        track_try!(writer.write_u32be(self.jitter));
        track_try!(writer.write_u32be(self.last_sr_timestamp));
        track_try!(writer.write_u32be(self.delay_since_last_sr));

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpReceiverReport {
    pub ssrc: Ssrc,
    pub reception_reports: Vec<ReceptionReport>,
    pub extensions: Vec<u8>,
}
impl RtcpReceiverReport {
    pub fn new(ssrc: Ssrc) -> Self {
        RtcpReceiverReport {
            ssrc: ssrc,
            reception_reports: Vec::new(),
            extensions: Vec::new(),
        }
    }
}
impl ReadFrom for RtcpReceiverReport {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (reception_report_count, payload) = track_try!(read_sctp(reader, RTCP_PACKET_TYPE_RR));
        let reader = &mut &payload[..];

        let ssrc = track_try!(reader.read_u32be());

        let mut reception_reports = Vec::new();
        for _ in 0..reception_report_count {
            let report = track_try!(ReceptionReport::read_from(reader));
            reception_reports.push(report);
        }
        let extensions = track_try!(reader.read_all_bytes());

        Ok(RtcpReceiverReport {
               ssrc: ssrc,
               reception_reports: reception_reports,
               extensions: extensions,
           })
    }
}
impl WriteTo for RtcpReceiverReport {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut payload = Vec::new();
        track_try!((&mut payload).write_u32be(self.ssrc));
        for report in self.reception_reports.iter() {
            track_try!(report.write_to(&mut payload));
        }
        payload.extend(&self.extensions);

        track_assert!(self.reception_reports.len() <= 0b0001_1111,
                      ErrorKind::Invalid);
        track_try!(write_sctp(writer,
                              RTCP_PACKET_TYPE_RR,
                              self.reception_reports.len() as u8,
                              &payload));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSourceDescription {
    pub chunks: Vec<SdesChunk>,
}
impl RtcpSourceDescription {
    pub fn new() -> Self {
        RtcpSourceDescription { chunks: Vec::new() }
    }
}
impl ReadFrom for RtcpSourceDescription {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (source_count, payload) = track_try!(read_sctp(reader, RTCP_PACKET_TYPE_SDES));
        let reader = &mut &payload[..];

        let chunks = track_try!((0..source_count).map(|_| SdesChunk::read_from(reader)).collect());
        Ok(RtcpSourceDescription { chunks: chunks })
    }
}
impl WriteTo for RtcpSourceDescription {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut payload = Vec::new();
        for chunk in self.chunks.iter() {
            track_try!(chunk.write_to(&mut payload));
        }

        track_assert!(self.chunks.len() <= 0b0001_1111, ErrorKind::Invalid);
        track_try!(write_sctp(writer,
                              RTCP_PACKET_TYPE_SDES,
                              self.chunks.len() as u8,
                              &payload));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    pub ssrc_or_csrc: SsrcOrCsrc,
    pub items: Vec<SdesItem>,
}
impl ReadFrom for SdesChunk {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut read_bytes = 0;

        let ssrc_or_csrc = track_try!(reader.read_u32be());
        read_bytes += 4;

        let mut items = Vec::new();
        loop {
            let ty = track_try!(reader.read_u8());
            read_bytes += 1;

            if ty == SDES_ITEM_TYPE_END {
                break;
            }
            let len = track_try!(reader.read_u8()) as usize;
            let text = track_try!(reader.read_string(len));
            read_bytes += 1 + len;
            let item = match ty {
                SDES_ITEM_TYPE_CNAME => SdesItem::Cname(text),
                SDES_ITEM_TYPE_NAME => SdesItem::Name(text),
                SDES_ITEM_TYPE_EMAIL => SdesItem::Email(text),
                SDES_ITEM_TYPE_PHONE => SdesItem::Phone(text),
                SDES_ITEM_TYPE_LOC => SdesItem::Loc(text),
                SDES_ITEM_TYPE_TOOL => SdesItem::Tool(text),
                SDES_ITEM_TYPE_NOTE => SdesItem::Note(text),
                SDES_ITEM_TYPE_PRIV => SdesItem::Priv(text),
                _ => track_panic!(ErrorKind::Unsupported, "Unknown SDES item type: {}", ty),
            };
            items.push(item);
        }
        let padding_len = (4 - read_bytes % 4) % 4;
        track_try!(reader.read_bytes(padding_len as usize)); // discard

        Ok(SdesChunk {
               ssrc_or_csrc: ssrc_or_csrc,
               items: items,
           })
    }
}
impl WriteTo for SdesChunk {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut write_bytes = 0;

        track_try!(writer.write_u32be(self.ssrc_or_csrc));
        write_bytes += 4;

        for item in self.items.iter() {
            track_try!(writer.write_u8(item.item_type()));
            write_bytes += 1;

            let text = item.text();
            track_assert!(text.len() <= 0xFFFF, ErrorKind::Invalid);
            track_try!(writer.write_u16be(text.len() as u16));
            track_try!(writer.write_all(text.as_bytes()));
            write_bytes += 2 + text.len();
        }
        track_try!(writer.write_u8(SDES_ITEM_TYPE_END));
        write_bytes += 1;

        let padding_len = (4 - write_bytes % 4) % 4;
        for _ in 0..padding_len {
            track_try!(writer.write_u8(0));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdesItem {
    Cname(String),
    Name(String),
    Email(String),
    Phone(String),
    Loc(String),
    Tool(String),
    Note(String),
    Priv(String),
}
impl SdesItem {
    pub fn item_type(&self) -> u8 {
        match *self {
            SdesItem::Cname(_) => SDES_ITEM_TYPE_CNAME,
            SdesItem::Name(_) => SDES_ITEM_TYPE_NAME,
            SdesItem::Email(_) => SDES_ITEM_TYPE_EMAIL,
            SdesItem::Phone(_) => SDES_ITEM_TYPE_PHONE,
            SdesItem::Loc(_) => SDES_ITEM_TYPE_LOC,
            SdesItem::Tool(_) => SDES_ITEM_TYPE_TOOL,
            SdesItem::Note(_) => SDES_ITEM_TYPE_NOTE,
            SdesItem::Priv(_) => SDES_ITEM_TYPE_PRIV,
        }
    }
    pub fn text(&self) -> &str {
        match *self {
            SdesItem::Cname(ref t) => t,
            SdesItem::Name(ref t) => t,
            SdesItem::Email(ref t) => t,
            SdesItem::Phone(ref t) => t,
            SdesItem::Loc(ref t) => t,
            SdesItem::Tool(ref t) => t,
            SdesItem::Note(ref t) => t,
            SdesItem::Priv(ref t) => t,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpGoodbye {
    pub ssrc_csrc_list: Vec<SsrcOrCsrc>,
    pub reason: Option<String>,
}
impl RtcpGoodbye {
    pub fn new() -> Self {
        RtcpGoodbye {
            ssrc_csrc_list: Vec::new(),
            reason: None,
        }
    }
}
impl ReadFrom for RtcpGoodbye {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (source_count, payload) = track_try!(read_sctp(reader, RTCP_PACKET_TYPE_BYE));
        let reader = &mut &payload[..];

        let list = track_try!((0..source_count).map(|_| reader.read_u32be()).collect());
        let mut reason = None;
        if let Ok(len) = reader.read_u8() {
            reason = Some(track_try!(reader.read_string(len as usize)));
        }
        Ok(RtcpGoodbye {
               ssrc_csrc_list: list,
               reason: reason,
           })
    }
}
impl WriteTo for RtcpGoodbye {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut payload = Vec::new();
        for x in self.ssrc_csrc_list.iter() {
            track_try!((&mut payload).write_u32be(*x));
        }
        if let Some(ref reason) = self.reason {
            track_assert!(reason.len() <= 0xFF, ErrorKind::Invalid);
            track_try!((&mut payload).write_u8(reason.len() as u8));
            track_try!((&mut payload).write_all(reason.as_bytes()));

            let padding_len = (4 - (reason.len() + 1) % 4) % 4;
            for _ in 0..padding_len {
                track_try!((&mut payload).write_u8(0));
            }
        }

        track_assert!(self.ssrc_csrc_list.len() <= 0b0001_1111, ErrorKind::Invalid);
        track_try!(write_sctp(writer,
                              RTCP_PACKET_TYPE_BYE,
                              self.ssrc_csrc_list.len() as u8,
                              &payload));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpApplicationDefined {
    pub subtype: U5,
    pub ssrc_or_csrc: SsrcOrCsrc,
    pub name: [u8; 4],
    pub data: Vec<u8>,
}
impl ReadFrom for RtcpApplicationDefined {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (subtype, payload) = track_try!(read_sctp(reader, RTCP_PACKET_TYPE_APP));
        let reader = &mut &payload[..];

        let ssrc_or_csrc = track_try!(reader.read_u32be());
        let mut name = [0; 4];
        track_try!(reader.read_exact(&mut name));
        let data = track_try!(reader.read_all_bytes());
        Ok(RtcpApplicationDefined {
               subtype: subtype,
               ssrc_or_csrc: ssrc_or_csrc,
               name: name,
               data: data,
           })
    }
}
impl WriteTo for RtcpApplicationDefined {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let mut payload = Vec::new();
        track_try!((&mut payload).write_u32be(self.ssrc_or_csrc));
        payload.extend(&self.name);
        payload.extend(&self.data);

        track_assert!(self.subtype <= 0b0001_1111, ErrorKind::Invalid);
        track_try!(write_sctp(writer, RTCP_PACKET_TYPE_APP, self.subtype, &payload));
        Ok(())
    }
}
