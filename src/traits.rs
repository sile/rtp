use std::io::{Read, Write};

use Result;

pub trait Packet {}

// TODO: DecodePacket(?)
pub trait ReadPacket {
    type Packet: Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet>;
    fn supports_type(&self, packet_type: u8) -> bool;
}

pub trait WritePacket {
    type Packet: Packet;
    fn write_packet<W: Write>(&mut self, writer: &mut W, packet: &Self::Packet) -> Result<()>;
}

pub trait RtpPacket: Packet {}
pub trait RtcpPacket: Packet {}
