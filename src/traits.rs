use packet::Packet;
use types::U7;

pub trait RtpPacket: Packet {
    fn supports_type(payload_type: U7) -> bool;
}
pub trait RtcpPacket: Packet {
    fn supports_type(packet_type: u8) -> bool;
}
