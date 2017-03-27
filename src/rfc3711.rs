use std::io::Read;
use crypto;
use num::BigUint;
use splay_tree::SplaySet;
use handy_async::sync_io::{ReadExt, WriteExt};

use {Result, ErrorKind};
use io::{ReadFrom, WriteTo};
use types::U48;
use traits::{ReadPacket, RtpPacket, RtcpPacket};
use rfc3550;

pub type PacketIndex = U48;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AesCm,
    AesF8,
    Null,
}
impl Default for EncryptionAlgorithm {
    fn default() -> Self {
        EncryptionAlgorithm::AesCm
    }
}

// https://tools.ietf.org/html/rfc3711#section-3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpContext {
    // TODO: support other fields
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
    pub rollover_counter: u32,
    pub highest_recv_seq_num: u16,
    pub encryption: EncryptionAlgorithm,
    pub replay_list: SplaySet<PacketIndex>,
    pub session_encr_key: Vec<u8>,
    pub session_salt_key: Vec<u8>,
    pub session_auth_key: Vec<u8>,
    pub auth_tag_len: usize,
}
impl SrtpContext {
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        // TODO: support MKI
        SrtpContext {
            master_key: Vec::from(master_key),
            master_salt: Vec::from(master_salt),
            rollover_counter: 0,
            highest_recv_seq_num: 0,
            encryption: EncryptionAlgorithm::default(),
            replay_list: SplaySet::new(),
            session_encr_key: vec![0; 128 / 8],
            session_salt_key: vec![0; 112 / 8],
            session_auth_key: vec![0; 160 / 8],
            auth_tag_len: 80 / 8,
        }
    }
    pub fn update_session_keys(&mut self) {
        let index = ((self.rollover_counter as u64) << 16) + self.highest_recv_seq_num as u64;
        let index = BigUint::from(index);

        let enc_key_id = BigUint::from_bytes_be(&[0, 0, 0, 0, 0, 0, 0]) + index.clone();
        let auth_key_id = BigUint::from_bytes_be(&[1, 0, 0, 0, 0, 0, 0]) + index.clone();
        let salt_key_id = BigUint::from_bytes_be(&[2, 0, 0, 0, 0, 0, 0]) + index.clone();
        let master_salt = BigUint::from_bytes_be(&self.master_salt);

        self.session_encr_key = prf_n(&self.master_key,
                                      enc_key_id ^ master_salt.clone(),
                                      self.session_encr_key.len());
        self.session_auth_key = prf_n(&self.master_key,
                                      auth_key_id ^ master_salt.clone(),
                                      self.session_auth_key.len());
        self.session_salt_key = prf_n(&self.master_key,
                                      salt_key_id ^ master_salt.clone(),
                                      self.session_salt_key.len());
    }
    pub fn authenticate(&self, packet: &[u8]) -> Result<()> {
        let auth_portion = &packet[..packet.len() - self.auth_tag_len];
        let auth_tag = &packet[packet.len() - self.auth_tag_len..];

        let mut auth_bytes = Vec::from(auth_portion);
        track_try!((&mut auth_bytes).write_u32be(self.rollover_counter));

        let mut expected_tag = hmac_hash_sha1(&self.session_auth_key, &auth_bytes);
        expected_tag.truncate(self.auth_tag_len);
        track_assert_eq!(auth_tag, &expected_tag[..], ErrorKind::Invalid);
        Ok(())
    }
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let reader = &mut &packet[..];
        let header = track_try!(rfc3550::RtpFixedHeader::read_from(reader));
        let encrypted_portion = &reader[0..reader.len() - self.auth_tag_len];

        let index = ((self.rollover_counter as u64) << 32) + (header.seq_num as u64);
        let iv = BigUint::from_bytes_be(&self.session_salt_key) << 16;
        let iv = iv ^ (BigUint::from(header.ssrc) << 64);
        let iv = iv ^ (BigUint::from(index) << 16);
        let iv = &iv.to_bytes_be()[0..self.session_encr_key.len()];

        let mut ctr =
            crypto::aes::ctr(crypto::aes::KeySize::KeySize128, &self.session_encr_key, iv);
        let block_size = self.session_encr_key.len();

        let mut decrypted: Vec<u8> = Vec::new();
        track_try!(header.write_to(&mut decrypted));

        for block in encrypted_portion.chunks(block_size) {
            let input = [0; 16];
            let mut output = [0; 16];
            ctr.process(&input[..], &mut output[..]);

            for (a, b) in block.iter().zip(output.iter()) {
                decrypted.push(*a ^ *b);
            }
        }

        Ok(decrypted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtcpContext {
    // TODO: support other fields
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
    pub highest_recv_index: PacketIndex, // NOTE: 47-bits
    pub encryption: EncryptionAlgorithm,
    pub replay_list: SplaySet<PacketIndex>,
    pub session_encr_key: Vec<u8>,
    pub session_salt_key: Vec<u8>,
    pub session_auth_key: Vec<u8>,
    pub auth_tag_len: usize,
}
impl SrtcpContext {
    pub fn new(master_key: &[u8], master_salt: &[u8]) -> Self {
        // TODO: support MKI
        SrtcpContext {
            master_key: Vec::from(master_key),
            master_salt: Vec::from(master_salt),
            highest_recv_index: 0,
            encryption: EncryptionAlgorithm::default(),
            replay_list: SplaySet::new(),
            session_encr_key: vec![0; 128 / 8],
            session_salt_key: vec![0; 112 / 8],
            session_auth_key: vec![0; 160 / 8],
            auth_tag_len: 80 / 8,
        }
    }
    pub fn update_session_keys(&mut self) {
        // See: https://tools.ietf.org/html/rfc3711#section-4.3.2
        let index = BigUint::from(self.highest_recv_index);

        let enc_key_id = BigUint::from_bytes_be(&[3, 0, 0, 0, 0, 0, 0]) + index.clone();
        let auth_key_id = BigUint::from_bytes_be(&[4, 0, 0, 0, 0, 0, 0]) + index.clone();
        let salt_key_id = BigUint::from_bytes_be(&[5, 0, 0, 0, 0, 0, 0]) + index.clone();
        let master_salt = BigUint::from_bytes_be(&self.master_salt);

        self.session_encr_key = prf_n(&self.master_key,
                                      enc_key_id ^ master_salt.clone(),
                                      self.session_encr_key.len());
        self.session_auth_key = prf_n(&self.master_key,
                                      auth_key_id ^ master_salt.clone(),
                                      self.session_auth_key.len());
        self.session_salt_key = prf_n(&self.master_key,
                                      salt_key_id ^ master_salt.clone(),
                                      self.session_salt_key.len());
    }
    pub fn authenticate(&self, packet: &[u8]) -> Result<()> {
        let auth_portion = &packet[..packet.len() - self.auth_tag_len];
        let auth_tag = &packet[packet.len() - self.auth_tag_len..];

        let mut expected_tag = hmac_hash_sha1(&self.session_auth_key, &auth_portion);
        expected_tag.truncate(self.auth_tag_len);
        track_assert_eq!(auth_tag, &expected_tag[..], ErrorKind::Invalid);
        Ok(())
    }
    pub fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        let index = track_try!((&mut &packet[packet.len() - self.auth_tag_len - 4..]).read_u32be());
        let is_encrypted = index & 0x8000_0000 != 0;
        if !is_encrypted {
            return Ok(Vec::from(&packet[..packet.len() - self.auth_tag_len - 4]));
        }
        let index = index & 0x7FFF_FFFF;

        let reader = &mut &packet[..];
        let _ = track_try!(reader.read_u32be());
        let ssrc = track_try!(reader.read_u32be());
        let encrypted_portion = &reader[0..reader.len() - self.auth_tag_len - 4];

        let iv = BigUint::from_bytes_be(&self.session_salt_key) << 16;
        let iv = iv ^ (BigUint::from(ssrc) << 64);
        let iv = iv ^ (BigUint::from(index) << 16);
        let iv = &iv.to_bytes_be()[0..self.session_encr_key.len()];

        let mut ctr =
            crypto::aes::ctr(crypto::aes::KeySize::KeySize128, &self.session_encr_key, iv);
        let block_size = self.session_encr_key.len();

        let mut decrypted = Vec::from(&packet[..8]);

        for block in encrypted_portion.chunks(block_size) {
            let input = [0; 16];
            let mut output = [0; 16];
            ctr.process(&input[..], &mut output[..]);

            for (a, b) in block.iter().zip(output.iter()) {
                decrypted.push(*a ^ *b);
            }
        }

        Ok(decrypted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpPacketReader<T> {
    context: SrtpContext,
    inner: T,
}
impl<T> SrtpPacketReader<T>
    where T: ReadPacket,
          T::Packet: RtpPacket
{
    pub fn new(mut context: SrtpContext, inner: T) -> Self {
        context.update_session_keys();
        SrtpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtpPacketReader<T>
    where T: ReadPacket,
          T::Packet: RtpPacket
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        track_try!(self.context.authenticate(&packet_bytes));
        let decrypted_packet_bytes = track_try!(self.context.decrypt(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtcpPacketReader<T> {
    context: SrtcpContext,
    inner: T,
}
impl<T> SrtcpPacketReader<T>
    where T: ReadPacket,
          T::Packet: RtcpPacket
{
    pub fn new(mut context: SrtcpContext, inner: T) -> Self {
        context.update_session_keys();
        SrtcpPacketReader {
            context: context,
            inner: inner,
        }
    }
}
impl<T> ReadPacket for SrtcpPacketReader<T>
    where T: ReadPacket,
          T::Packet: RtcpPacket
{
    type Packet = T::Packet;
    fn read_packet<R: Read>(&mut self, reader: &mut R) -> Result<Self::Packet> {
        let packet_bytes = track_try!(reader.read_all_bytes());
        track_try!(self.context.authenticate(&packet_bytes));
        let decrypted_packet_bytes = track_try!(self.context.decrypt(&packet_bytes));
        track_err!(self.inner.read_packet(&mut &decrypted_packet_bytes[..]))
    }

    fn supports_type(&self, ty: u8) -> bool {
        self.inner.supports_type(ty)
    }
}

fn hmac_hash_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    use crypto::mac::Mac;
    let mut hmac = crypto::hmac::Hmac::new(crypto::sha1::Sha1::new(), key);
    hmac.input(data);
    Vec::from(hmac.result().code())
}

fn prf_n(master_key: &[u8], x: BigUint, n: usize) -> Vec<u8> {
    // https://tools.ietf.org/html/rfc3711#section-4.1.1
    let mut output = Vec::new();
    let mut ctr = crypto::aes::ctr(crypto::aes::KeySize::KeySize128,
                                   master_key,
                                   &(x << 16).to_bytes_be());
    for i in 0.. {
        let old_len = output.len();
        let new_len = output.len() + 16;
        output.resize(new_len, 0);

        let mut input = [0; 16];
        (&mut input[8..]).write_u64be(i).unwrap();
        ctr.process(&input[..], &mut output[old_len..]);
        if output.len() >= n {
            break;
        }
    }
    output.truncate(n);
    output
}

#[cfg(test)]
mod test {
    use rfc3550;
    use rfc4585;
    use super::*;

    #[test]
    fn rtp_decryption_works() {
        let master_key = [211, 77, 116, 243, 125, 116, 231, 95, 59, 219, 79, 118, 241, 189, 244,
                          119];
        let master_salt = [127, 31, 227, 93, 120, 247, 126, 117, 231, 159, 123, 235, 95, 122];

        let packet = [128, 0, 3, 92, 222, 161, 6, 76, 26, 163, 115, 130, 222, 0, 143, 87, 0, 227,
                      123, 91, 200, 238, 141, 220, 9, 191, 52, 111, 100, 62, 220, 158, 211, 79,
                      184, 199, 79, 182, 9, 248, 170, 82, 125, 152, 143, 206, 8, 152, 80, 207, 27,
                      183, 141, 77, 33, 60, 101, 180, 210, 146, 139, 170, 149, 13, 99, 75, 223,
                      156, 79, 71, 84, 119, 68, 236, 244, 163, 198, 175, 219, 160, 255, 9, 82,
                      169, 64, 112, 106, 4, 0, 246, 39, 29, 88, 15, 62, 174, 21, 253, 171, 198,
                      128, 61, 23, 43, 143, 255, 176, 125, 223, 23, 188, 90, 103, 139, 223, 56,
                      162, 35, 27, 225, 117, 243, 138, 163, 35, 79, 221, 201, 149, 154, 203, 255,
                      2, 23, 184, 184, 169, 32, 1, 138, 172, 60, 70, 240, 53, 11, 54, 81, 172,
                      214, 34, 136, 39, 152, 17, 247, 126, 199, 200, 184, 70, 7, 52, 191, 129,
                      239, 86, 78, 172, 229, 178, 112, 22, 125, 191, 164, 17, 193, 24, 152, 197,
                      146, 94, 74, 156, 171, 245, 239, 220, 205, 145, 206];

        let context = SrtpContext::new(&master_key, &master_salt);
        let mut rtp_reader = SrtpPacketReader::new(context, rfc3550::RtpPacketReader);
        let packet = rtp_reader.read_packet(&mut &packet[..]).unwrap();

        let expected_prefix = [0xbe, 0x9c, 0x8c, 0x86, 0x81, 0x80, 0x81, 0x86, 0x8d, 0x9c, 0xfd,
                               0x1b, 0x0d, 0x05, 0x01, 0x00, 0x01, 0x05, 0x0d, 0x1b, 0xff, 0x9b,
                               0x8d, 0x85, 0x81, 0x80, 0x81, 0x85, 0x8d, 0x9b, 0xff, 0x1b];

        assert_eq!(&packet.payload[..expected_prefix.len()],
                   &expected_prefix[..]);
    }

    #[test]
    fn rtcp_decryption_works() {
        let master_key = [254, 123, 44, 240, 174, 252, 53, 54, 2, 213, 123, 106, 85, 165, 5, 13];
        let master_salt = [77, 202, 202, 112, 81, 101, 219, 232, 143, 131, 160, 89, 15, 141];
        let packet = [128, 201, 0, 1, 194, 242, 138, 93, 67, 38, 193, 233, 60, 78, 188, 195, 230,
                      90, 19, 196, 152, 235, 136, 164, 15, 177, 174, 217, 207, 115, 148, 223, 109,
                      112, 71, 245, 16, 214, 216, 232, 87, 153, 5, 238, 72, 201, 223, 43, 69, 99,
                      54, 211, 118, 28, 227, 100, 161, 216, 90, 203, 99, 167, 215, 130, 151, 16,
                      128, 138, 128, 0, 0, 1, 126, 39, 201, 236, 161, 194, 6, 232, 194, 230];

        let context = SrtcpContext::new(&master_key, &master_salt);
        let mut rtcp_reader = SrtcpPacketReader::new(context, rfc4585::RtcpPacketReader);
        let packet = track_try_unwrap!(rtcp_reader.read_packet(&mut &packet[..]));
        println!("# {:?}", packet);
    }
}
