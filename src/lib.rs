#[macro_use]
extern crate trackable;
extern crate handy_async;

pub use error::{Error, ErrorKind};

pub mod io;
pub mod packet;
pub mod rfc3550;

mod error;

pub type Result<T> = ::std::result::Result<T, Error>;

pub mod types {
    pub type U2 = u8;
    pub type U4 = u8;
    pub type U5 = u8;
    pub type U7 = u8;
    pub type U24 = u32;
    pub type RtpTimestamp = u32;
    pub type Ssrc = u32;
    pub type Csrc = u32;
}

pub mod constants {
    pub const RTP_VERSION: u8 = 2;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}