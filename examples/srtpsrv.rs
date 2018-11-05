extern crate clap;
extern crate fibers;
extern crate futures;
#[macro_use]
extern crate trackable;
extern crate rtp;

use clap::{App, Arg};
use fibers::net::futures::RecvFrom;
use fibers::net::UdpSocket;
use fibers::{Executor, InPlaceExecutor, Spawn};
use futures::{Async, Future, Poll};
use rtp::rfc3550::RtpPacketReader;
use rtp::rfc3711::{SrtpContext, SrtpPacketReader};
use rtp::traits::ReadPacket;
use rtp::{Error, ErrorKind};
use trackable::error::ErrorKindExt;

fn main() {
    let matches = App::new("srtpsrv")
        .arg(
            Arg::with_name("PORT")
                .short("p")
                .takes_value(true)
                .default_value("6000"),
        ).arg(
            Arg::with_name("MASTER_KEY")
                .short("k")
                .takes_value(true)
                .default_value("d34d74f37d74e75f3bdb4f76f1bdf477"),
        ).arg(
            Arg::with_name("MASTER_SALT")
                .short("s")
                .takes_value(true)
                .default_value("7f1fe35d78f77e75e79f7beb5f7a"),
        ).get_matches();
    let port = matches.value_of("PORT").unwrap();
    let addr = format!("0.0.0.0:{}", port).parse().unwrap();

    let master_key = hex_str_to_bytes(matches.value_of("MASTER_KEY").unwrap());
    let master_salt = hex_str_to_bytes(matches.value_of("MASTER_SALT").unwrap());
    let context = SrtpContext::new(&master_key, &master_salt);
    let future = track_err!(UdpSocket::bind(addr))
        .and_then(move |socket| SrtpRecvLoop::new(socket, context));

    let mut executor = InPlaceExecutor::new().unwrap();
    let monitor = executor.spawn_monitor(future);
    let result = executor
        .run_fiber(monitor)
        .unwrap()
        .map_err(|e| e.unwrap_or_else(|| ErrorKind::Other.cause("disconnected")));
    track_try_unwrap!(result);
}

fn hex_str_to_bytes(s: &str) -> Vec<u8> {
    use std::u8;
    let mut bytes = Vec::new();
    for i in 0..s.len() / 2 {
        let b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}

struct SrtpRecvLoop {
    future: RecvFrom<Vec<u8>>,
    reader: SrtpPacketReader<RtpPacketReader>,
}
impl SrtpRecvLoop {
    fn new(socket: UdpSocket, context: SrtpContext) -> Self {
        let inner = RtpPacketReader;
        SrtpRecvLoop {
            future: socket.recv_from(vec![0; 4096]),
            reader: SrtpPacketReader::new(context, inner),
        }
    }
}
impl Future for SrtpRecvLoop {
    type Item = ();
    type Error = Error;
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        while let Async::Ready(v) = track_try!(self.future.poll().map_err(|e| e.2)) {
            let (socket, buf, size, peer) = v;
            let packet = track_try!(self.reader.read_packet(&mut &buf[..size]));
            println!("Recv packet from {}: {:?}", peer, packet);
            self.future = socket.recv_from(buf);
        }
        Ok(Async::NotReady)
    }
}
