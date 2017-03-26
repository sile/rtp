use packet::Packet;

pub trait RtpPacket: Packet {}
pub trait RtcpPacket: Packet {}
