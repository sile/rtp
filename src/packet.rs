use io::{ReadFrom, WriteTo};

pub trait Packet: ReadFrom + WriteTo {}
