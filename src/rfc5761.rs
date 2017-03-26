use std::io::{Read, Write};

use {Result, ErrorKind};
use io::{ReadFrom, WriteTo};
use traits::{RtpPacket, RtcpPacket};
use packet::Packet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MuxedPacket<T, U> {
    Rtp(T),
    Rtcp(U),
}
impl<T, U> Packet for MuxedPacket<T, U>
    where T: RtpPacket,
          U: RtcpPacket
{
}
impl<T, U> ReadFrom for MuxedPacket<T, U>
    where T: RtpPacket,
          U: RtcpPacket
{
    fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut buf = [0; 2];
        track_try!(reader.read_exact(&mut buf));

        let ty = buf[1];
        if U::supports_type(ty) {
            let reader = &mut (&buf[..]).chain(reader);
            track_err!(U::read_from(reader).map(MuxedPacket::Rtcp))
        } else if T::supports_type(ty & 0b0111_1111) {
            let reader = &mut (&buf[..]).chain(reader);
            track_err!(T::read_from(reader).map(MuxedPacket::Rtp))
        } else {
            track_panic!(ErrorKind::Unsupported,
                         "Unknown packet/payload type: {}",
                         ty)
        }
    }
}
impl<T, U> WriteTo for MuxedPacket<T, U>
    where T: RtpPacket,
          U: RtcpPacket
{
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            MuxedPacket::Rtp(ref p) => track_try!(p.write_to(writer)),
            MuxedPacket::Rtcp(ref p) => track_try!(p.write_to(writer)),
        }
        Ok(())
    }
}
