use std::io::{Read, Write};

use Result;

pub trait ReadFrom: Sized {
    fn read_from<R: Read>(reader: &mut R) -> Result<Self>;
}

pub trait WriteTo {
    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()>;
}
