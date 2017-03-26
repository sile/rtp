use std::io::{Read, Write};
use handy_async::sync_io::{ReadExt, WriteExt};

use {Result, ErrorKind};
use io::{ReadFrom, WriteTo};
use packet::Packet;
use traits;
use types::{U5, U6, U7, U13, Ssrc};
use constants::RTP_VERSION;
use rfc3550;

pub const RTCP_PACKET_TYPE_RTPFB: u8 = 205;
pub const RTCP_PACKET_TYPE_PSFB: u8 = 206;

pub const RTPFB_MESSAGE_TYPE_NACK: u8 = 1;

pub const PSFB_MESSAGE_TYPE_PLI: u8 = 1;
pub const PSFB_MESSAGE_TYPE_SLI: u8 = 2;
pub const PSFB_MESSAGE_TYPE_RPSI: u8 = 3;
pub const PSFB_MESSAGE_TYPE_AFB: u8 = 15;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    Sr(rfc3550::RtcpSenderReport),
    Rr(rfc3550::RtcpReceiverReport),
    Sdes(rfc3550::RtcpSourceDescription),
    Bye(rfc3550::RtcpGoodbye),
    App(rfc3550::RtcpApplicationDefined),
    Rtpfb(RtcpTransportLayerFeedback),
    Psfb(RtcpPayloadSpecificFeedback),
}
impl Packet for RtcpPacket {}
impl traits::RtcpPacket for RtcpPacket {}
impl ReadFrom for RtcpPacket {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0; 2];
        track_try!(reader.read_exact(&mut buf));

        let reader = &mut (&buf[..]).chain(reader);
        let packet_type = buf[1];
        match packet_type {
            rfc3550::RTCP_PACKET_TYPE_SR => {
                track_err!(rfc3550::RtcpSenderReport::read_from(reader).map(From::from))
            }
            rfc3550::RTCP_PACKET_TYPE_RR => {
                track_err!(rfc3550::RtcpReceiverReport::read_from(reader).map(From::from))
            }
            rfc3550::RTCP_PACKET_TYPE_SDES => {
                track_err!(rfc3550::RtcpSourceDescription::read_from(reader).map(From::from))
            }
            rfc3550::RTCP_PACKET_TYPE_BYE => {
                track_err!(rfc3550::RtcpGoodbye::read_from(reader).map(From::from))
            }
            rfc3550::RTCP_PACKET_TYPE_APP => {
                track_err!(rfc3550::RtcpApplicationDefined::read_from(reader).map(From::from))
            }
            RTCP_PACKET_TYPE_RTPFB => {
                track_err!(RtcpTransportLayerFeedback::read_from(reader).map(From::from))
            }
            RTCP_PACKET_TYPE_PSFB => {
                track_err!(RtcpPayloadSpecificFeedback::read_from(reader).map(From::from))
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
            RtcpPacket::Rtpfb(ref p) => track_err!(p.write_to(writer)),
            RtcpPacket::Psfb(ref p) => track_err!(p.write_to(writer)),
        }
    }
}
impl From<rfc3550::RtcpSenderReport> for RtcpPacket {
    fn from(f: rfc3550::RtcpSenderReport) -> Self {
        RtcpPacket::Sr(f)
    }
}
impl From<rfc3550::RtcpReceiverReport> for RtcpPacket {
    fn from(f: rfc3550::RtcpReceiverReport) -> Self {
        RtcpPacket::Rr(f)
    }
}
impl From<rfc3550::RtcpSourceDescription> for RtcpPacket {
    fn from(f: rfc3550::RtcpSourceDescription) -> Self {
        RtcpPacket::Sdes(f)
    }
}
impl From<rfc3550::RtcpGoodbye> for RtcpPacket {
    fn from(f: rfc3550::RtcpGoodbye) -> Self {
        RtcpPacket::Bye(f)
    }
}
impl From<rfc3550::RtcpApplicationDefined> for RtcpPacket {
    fn from(f: rfc3550::RtcpApplicationDefined) -> Self {
        RtcpPacket::App(f)
    }
}
impl From<RtcpTransportLayerFeedback> for RtcpPacket {
    fn from(f: RtcpTransportLayerFeedback) -> Self {
        RtcpPacket::Rtpfb(f)
    }
}
impl From<RtcpPayloadSpecificFeedback> for RtcpPacket {
    fn from(f: RtcpPayloadSpecificFeedback) -> Self {
        RtcpPacket::Psfb(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpTransportLayerFeedback {
    Nack(GenericNack),
}
impl Packet for RtcpTransportLayerFeedback {}
impl traits::RtcpPacket for RtcpTransportLayerFeedback {}
impl ReadFrom for RtcpTransportLayerFeedback {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (fb_message_type, rest) = track_try!(read_common(reader, RTCP_PACKET_TYPE_RTPFB));
        match fb_message_type {
            RTPFB_MESSAGE_TYPE_NACK => {
                track_err!(GenericNack::read_from(&mut &rest[..])).map(From::from)
            }
            _ => {
                track_panic!(ErrorKind::Unsupported,
                             "Unknown feedback type: {}",
                             fb_message_type)
            }
        }
    }
}
impl WriteTo for RtcpTransportLayerFeedback {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            RtcpTransportLayerFeedback::Nack(ref f) => {
                let payload = track_try!(f.to_bytes());
                track_err!(write_common(writer,
                                        RTCP_PACKET_TYPE_RTPFB,
                                        RTPFB_MESSAGE_TYPE_NACK,
                                        &payload))
            }
        }
    }
}
impl From<GenericNack> for RtcpTransportLayerFeedback {
    fn from(f: GenericNack) -> Self {
        RtcpTransportLayerFeedback::Nack(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPayloadSpecificFeedback {
    Pli(PictureLossIndication),
    Sli(SliceLossIndication),
    Rpsi(ReferencePictureSelectionIndication),
    Afb(ApplicationLayerFeedback),
}
impl Packet for RtcpPayloadSpecificFeedback {}
impl traits::RtcpPacket for RtcpPayloadSpecificFeedback {}
impl ReadFrom for RtcpPayloadSpecificFeedback {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let (fb_message_type, rest) = track_try!(read_common(reader, RTCP_PACKET_TYPE_PSFB));
        let reader = &mut &rest[..];
        match fb_message_type {
            PSFB_MESSAGE_TYPE_PLI => {
                track_err!(PictureLossIndication::read_from(reader).map(From::from))
            }
            PSFB_MESSAGE_TYPE_SLI => {
                track_err!(SliceLossIndication::read_from(reader).map(From::from))
            }
            PSFB_MESSAGE_TYPE_RPSI => {
                track_err!(ReferencePictureSelectionIndication::read_from(reader).map(From::from))
            }
            PSFB_MESSAGE_TYPE_AFB => {
                track_err!(ApplicationLayerFeedback::read_from(reader).map(From::from))
            }
            _ => {
                track_panic!(ErrorKind::Unsupported,
                             "Unknown feedback type: {}",
                             fb_message_type)
            }
        }
    }
}
impl WriteTo for RtcpPayloadSpecificFeedback {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            RtcpPayloadSpecificFeedback::Pli(ref f) => {
                let payload = track_try!(f.to_bytes());
                track_err!(write_common(writer,
                                        RTCP_PACKET_TYPE_PSFB,
                                        PSFB_MESSAGE_TYPE_PLI,
                                        &payload))
            }
            RtcpPayloadSpecificFeedback::Sli(ref f) => {
                let payload = track_try!(f.to_bytes());
                track_err!(write_common(writer,
                                        RTCP_PACKET_TYPE_PSFB,
                                        PSFB_MESSAGE_TYPE_SLI,
                                        &payload))
            }
            RtcpPayloadSpecificFeedback::Rpsi(ref f) => {
                let payload = track_try!(f.to_bytes());
                track_err!(write_common(writer,
                                        RTCP_PACKET_TYPE_PSFB,
                                        PSFB_MESSAGE_TYPE_RPSI,
                                        &payload))
            }
            RtcpPayloadSpecificFeedback::Afb(ref f) => {
                let payload = track_try!(f.to_bytes());
                track_err!(write_common(writer,
                                        RTCP_PACKET_TYPE_PSFB,
                                        PSFB_MESSAGE_TYPE_AFB,
                                        &payload))
            }
        }
    }
}
impl From<PictureLossIndication> for RtcpPayloadSpecificFeedback {
    fn from(f: PictureLossIndication) -> Self {
        RtcpPayloadSpecificFeedback::Pli(f)
    }
}
impl From<SliceLossIndication> for RtcpPayloadSpecificFeedback {
    fn from(f: SliceLossIndication) -> Self {
        RtcpPayloadSpecificFeedback::Sli(f)
    }
}
impl From<ReferencePictureSelectionIndication> for RtcpPayloadSpecificFeedback {
    fn from(f: ReferencePictureSelectionIndication) -> Self {
        RtcpPayloadSpecificFeedback::Rpsi(f)
    }
}
impl From<ApplicationLayerFeedback> for RtcpPayloadSpecificFeedback {
    fn from(f: ApplicationLayerFeedback) -> Self {
        RtcpPayloadSpecificFeedback::Afb(f)
    }
}

fn write_common<W: Write>(writer: &mut W,
                          packet_type: u8,
                          fb_message_type: U5,
                          payload: &[u8])
                          -> Result<()> {
    track_assert_eq!(payload.len() % 4, 0, ErrorKind::Invalid);

    track_try!(writer.write_u8(RTP_VERSION << 6 | fb_message_type));
    track_try!(writer.write_u8(packet_type));

    let word_count = payload.len() / 4;
    track_assert!(word_count < 0x10000, ErrorKind::Invalid);

    track_try!(writer.write_u16be(word_count as u16));
    track_try!(writer.write_all(payload));

    Ok(())
}

fn read_common<R: Read>(reader: &mut R, expected_type: u8) -> Result<(U5, Vec<u8>)> {
    let b = track_try!(reader.read_u8());
    track_assert_eq!(b >> 6,
                     RTP_VERSION,
                     ErrorKind::Unsupported,
                     "Unsupported RTP version: {}",
                     b >> 6);
    let padding = (b & 0b0010_0000) != 0;
    let fb_message_type = b & 0b0001_1111;

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

    Ok((fb_message_type, payload))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericNack {
    pub sender_ssrc: Ssrc,
    pub media_ssrc: Ssrc,
    pub packet_id: u16,
    pub lost_packets_bitmask: u16,
}
impl ReadFrom for GenericNack {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let sender_ssrc = track_try!(reader.read_u32be());
        let media_ssrc = track_try!(reader.read_u32be());
        let packet_id = track_try!(reader.read_u16be());
        let lost_packets_bitmask = track_try!(reader.read_u16be());
        Ok(GenericNack {
               sender_ssrc: sender_ssrc,
               media_ssrc: media_ssrc,
               packet_id: packet_id,
               lost_packets_bitmask: lost_packets_bitmask,
           })
    }
}
impl WriteTo for GenericNack {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_try!(writer.write_u32be(self.sender_ssrc));
        track_try!(writer.write_u32be(self.media_ssrc));
        track_try!(writer.write_u16be(self.packet_id));
        track_try!(writer.write_u16be(self.lost_packets_bitmask));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PictureLossIndication {
    pub sender_ssrc: Ssrc,
    pub media_ssrc: Ssrc,
}
impl ReadFrom for PictureLossIndication {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let sender_ssrc = track_try!(reader.read_u32be());
        let media_ssrc = track_try!(reader.read_u32be());
        Ok(PictureLossIndication {
               sender_ssrc: sender_ssrc,
               media_ssrc: media_ssrc,
           })
    }
}
impl WriteTo for PictureLossIndication {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_try!(writer.write_u32be(self.sender_ssrc));
        track_try!(writer.write_u32be(self.media_ssrc));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceLossIndication {
    pub sender_ssrc: Ssrc,
    pub media_ssrc: Ssrc,
    pub first: u16,
    pub number: U13,
    pub picture_id: U6,
}
impl ReadFrom for SliceLossIndication {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let sender_ssrc = track_try!(reader.read_u32be());
        let media_ssrc = track_try!(reader.read_u32be());
        let first = track_try!(reader.read_u16be());
        let num_and_pic = track_try!(reader.read_u16be());
        let number = num_and_pic >> 6;
        let picture_id = (num_and_pic as u8) & 0b0011_1111;
        Ok(SliceLossIndication {
               sender_ssrc: sender_ssrc,
               media_ssrc: media_ssrc,
               first: first,
               number: number,
               picture_id: picture_id,
           })
    }
}
impl WriteTo for SliceLossIndication {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_try!(writer.write_u32be(self.sender_ssrc));
        track_try!(writer.write_u32be(self.media_ssrc));
        track_try!(writer.write_u16be(self.first));
        track_try!(writer.write_u16be((self.number << 6) + (self.picture_id as u16)));
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferencePictureSelectionIndication {
    pub sender_ssrc: Ssrc,
    pub media_ssrc: Ssrc,
    pub rtp_payload_type: U7,
    pub information: Vec<u8>,
}
impl ReadFrom for ReferencePictureSelectionIndication {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let sender_ssrc = track_try!(reader.read_u32be());
        let media_ssrc = track_try!(reader.read_u32be());
        let padding = track_try!(reader.read_u8());
        let rtp_payload_type = track_try!(reader.read_u8());
        track_assert_eq!(rtp_payload_type & 0b1000_0000, 0, ErrorKind::Invalid);
        let info_len = track_try!(reader.read_u16be());
        let info = track_try!(reader.read_bytes(info_len as usize));
        let _ = track_try!(reader.read_bytes(padding as usize));
        Ok(ReferencePictureSelectionIndication {
               sender_ssrc: sender_ssrc,
               media_ssrc: media_ssrc,
               rtp_payload_type: rtp_payload_type,
               information: info,
           })
    }
}
impl WriteTo for ReferencePictureSelectionIndication {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_try!(writer.write_u32be(self.sender_ssrc));
        track_try!(writer.write_u32be(self.media_ssrc));

        let len = 1 + 1 + 2 + self.information.len();
        let padding_len = (4 - len % 4) % 4;
        track_try!(writer.write_u8(padding_len as u8));

        track_assert_eq!(self.rtp_payload_type & 0b1000_0000, 0, ErrorKind::Invalid);
        track_try!(writer.write_u8(self.rtp_payload_type));

        track_assert!(self.information.len() <= 0xFFFF, ErrorKind::Invalid);
        track_try!(writer.write_u16be(self.information.len() as u16));
        track_try!(writer.write_all(&self.information));

        for _ in 0..padding_len {
            track_try!(writer.write_u8(0));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationLayerFeedback {
    pub sender_ssrc: Ssrc,
    pub media_ssrc: Ssrc,
    pub data: Vec<u8>,
}
impl ReadFrom for ApplicationLayerFeedback {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let sender_ssrc = track_try!(reader.read_u32be());
        let media_ssrc = track_try!(reader.read_u32be());
        let data = track_try!(reader.read_all_bytes());
        Ok(ApplicationLayerFeedback {
               sender_ssrc: sender_ssrc,
               media_ssrc: media_ssrc,
               data: data,
           })
    }
}
impl WriteTo for ApplicationLayerFeedback {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        track_try!(writer.write_u32be(self.sender_ssrc));
        track_try!(writer.write_u32be(self.media_ssrc));
        track_try!(writer.write_all(&self.data));
        Ok(())
    }
}
