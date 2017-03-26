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
        let marker = (buf[1] & 0b1000_0000) != 0;
        if !marker {
            let reader = &mut (&buf[..]).chain(reader);
            track_err!(T::read_from(reader).map(MuxedPacket::Rtp))
        } else {
            let reader = &mut (&buf[..]).chain(reader);
            track_err!(U::read_from(reader).map(MuxedPacket::Rtcp))
        }
    }
}
impl<T, U> WriteTo for MuxedPacket<T, U>
    where T: RtpPacket,
          U: RtcpPacket
{
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match *self {
            MuxedPacket::Rtp(ref p) => {
                let mut buf = Vec::new();
                track_try!(p.write_to(&mut buf));
                track_assert!(buf.len() >= 2, ErrorKind::Other);
                buf[1] &= 0b0111_1111;
                track_try!(writer.write_all(&buf));
            }
            MuxedPacket::Rtcp(ref p) => track_try!(p.write_to(writer)),
        }
        Ok(())
    }
}
