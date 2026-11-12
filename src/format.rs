//! On-wire format for this tool version. The version byte is a fail-closed
//! check, not a compatibility promise. There is no reader for any other
//! version, and none should be added just to open old files.
//!
//! Sealed file (`AGRS`):
//! `magic || version || threshold || count || key_bytes:u16be || group[16] ||
//! nonce_prefix[20]` then chunks of `last:u8 || ciphertext_len:u32be ||
//! ciphertext` until `last = 1`.
//!
//! Share (`AGRH`):
//! `magic || version || index || threshold || count || key_bytes:u16be ||
//! group[16] || commitment[32] || flags || body_len:u32be || body`.
//! `flags` bit 0 means the body is a password-sealed Shamir share. Otherwise
//! the body is the Shamir share itself (`x || y[key_bytes]`).

use {
    crate::error::Error,
    anyhow::{bail, Context, Result},
    sha2::{Digest, Sha256},
    std::io::{Read, Write},
};

pub(crate) const FORMAT_VERSION: u8 = 2;
pub(crate) const SEALED_MAGIC: &[u8; 4] = b"AGRS";
pub(crate) const SHARE_MAGIC: &[u8; 4] = b"AGRH";
pub(crate) const HEADER_LEN: usize = 4 + 1 + 1 + 1 + 2 + 16 + 20;
const SHARE_HEADER_LEN: usize = 4 + 1 + 1 + 1 + 1 + 2 + 16 + 32 + 1 + 4;
const FLAG_PASSWORD: u8 = 0x01;
/// Ciphertext of one 64 KiB chunk plus one Poly1305 tag per key layer. The
/// maximum is 32 layers. Larger lengths are rejected.
pub(crate) const MAX_CHUNK_CIPHERTEXT: usize = 64 * 1024 + 16 * 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SealedHeader {
    pub(crate) threshold: u8,
    pub(crate) count: u8,
    pub(crate) key_bytes: u16,
    pub(crate) group: [u8; 16],
    pub(crate) nonce_prefix: [u8; 20],
}

impl SealedHeader {
    pub(crate) fn write_to<W: Write>(&self, mut out: W) -> Result<()> {
        out.write_all(SEALED_MAGIC)?;
        out.write_all(&[FORMAT_VERSION, self.threshold, self.count])?;
        out.write_all(&self.key_bytes.to_be_bytes())?;
        out.write_all(&self.group)?;
        out.write_all(&self.nonce_prefix)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut bytes = vec![0u8; HEADER_LEN];
        reader.read_exact(&mut bytes).context("sealed header is truncated")?;
        Self::parse(&bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != HEADER_LEN || &bytes[0..4] != SEALED_MAGIC {
            bail!("not an agree sealed secret");
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: bytes[4],
                expected: FORMAT_VERSION,
            }
            .into());
        }
        let mut group = [0u8; 16];
        let mut nonce_prefix = [0u8; 20];
        group.copy_from_slice(&bytes[9..25]);
        nonce_prefix.copy_from_slice(&bytes[25..45]);
        Ok(Self {
            threshold: bytes[5],
            count: bytes[6],
            key_bytes: u16::from_be_bytes(bytes[7..9].try_into().expect("2 bytes")),
            group,
            nonce_prefix,
        })
    }
}

/// One share after the password, if any, has been removed.
#[derive(Clone, Debug)]
pub(crate) struct ShareRecord {
    pub(crate) index: u8,
    pub(crate) threshold: u8,
    pub(crate) count: u8,
    pub(crate) key_bytes: u16,
    pub(crate) group: [u8; 16],
    pub(crate) commitment: [u8; 32],
    pub(crate) password: bool,
    pub(crate) body: Vec<u8>,
}

impl ShareRecord {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.index == 0 {
            bail!("share index 0 is not valid");
        }
        let mut flags = 0u8;
        if self.password {
            flags |= FLAG_PASSWORD;
        }
        let len = u32::try_from(self.body.len()).context("share body is too large")?;
        let mut out = Vec::with_capacity(SHARE_HEADER_LEN + self.body.len());
        out.extend_from_slice(SHARE_MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.index);
        out.push(self.threshold);
        out.push(self.count);
        out.extend_from_slice(&self.key_bytes.to_be_bytes());
        out.extend_from_slice(&self.group);
        out.extend_from_slice(&self.commitment);
        out.push(flags);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.body);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SHARE_HEADER_LEN || &bytes[0..4] != SHARE_MAGIC {
            bail!("not an agree share");
        }
        if bytes[4] != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion {
                found: bytes[4],
                expected: FORMAT_VERSION,
            }
            .into());
        }
        let index = bytes[5];
        if index == 0 {
            bail!("share index 0 is not valid");
        }
        let mut group = [0u8; 16];
        let mut commitment = [0u8; 32];
        group.copy_from_slice(&bytes[10..26]);
        commitment.copy_from_slice(&bytes[26..58]);
        let flags = bytes[58];
        if flags & !FLAG_PASSWORD != 0 {
            bail!("share has unknown flags");
        }
        let body_len = u32::from_be_bytes(bytes[59..63].try_into().expect("4 bytes")) as usize;
        let body = bytes.get(63..63 + body_len).context("share body is truncated")?;
        if bytes.len() != 63 + body_len {
            bail!("share has trailing bytes");
        }
        Ok(Self {
            index,
            threshold: bytes[6],
            count: bytes[7],
            key_bytes: u16::from_be_bytes(bytes[8..10].try_into().expect("2 bytes")),
            group,
            commitment,
            password: flags & FLAG_PASSWORD != 0,
            body: body.to_vec(),
        })
    }

    pub(crate) fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 16 + 3 + 32);
        aad.extend_from_slice(b"agree-share-v2");
        aad.extend_from_slice(&self.group);
        aad.push(self.index);
        aad.push(self.threshold);
        aad.push(self.count);
        aad.extend_from_slice(&self.key_bytes.to_be_bytes());
        aad.extend_from_slice(&self.commitment);
        aad
    }
}

/// Reads a sealed stream, hashing exactly the bytes that belong to the format.
pub(crate) struct SealedReader<R> {
    inner: R,
    hasher: Sha256,
    pub(crate) header: SealedHeader,
}

impl<R: Read> SealedReader<R> {
    pub(crate) fn open(mut inner: R) -> Result<Self> {
        let mut header_bytes = [0u8; HEADER_LEN];
        inner
            .read_exact(&mut header_bytes)
            .context("sealed secret is truncated")?;
        let header = SealedHeader::parse(&header_bytes)?;
        let mut hasher = Sha256::new();
        hasher.update(header_bytes);
        Ok(Self { inner, hasher, header })
    }

    pub(crate) fn next_chunk(&mut self) -> Result<Option<(bool, Vec<u8>)>> {
        let mut last = [0u8; 1];
        match self.inner.read(&mut last)? {
            | 0 => return Ok(None),
            | 1 => {},
            | _ => unreachable!("one-byte read"),
        }
        let mut len_bytes = [0u8; 4];
        self.inner
            .read_exact(&mut len_bytes)
            .context("sealed chunk length is truncated")?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > MAX_CHUNK_CIPHERTEXT {
            bail!("sealed chunk is too large");
        }
        let mut ciphertext = vec![0u8; len];
        self.inner
            .read_exact(&mut ciphertext)
            .context("sealed chunk is truncated")?;
        self.hasher.update(last);
        self.hasher.update(len_bytes);
        self.hasher.update(&ciphertext);
        Ok(Some((last[0] == 1, ciphertext)))
    }

    pub(crate) fn commitment(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

pub(crate) struct SealedWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> SealedWriter<W> {
    pub(crate) fn new(mut inner: W, header: &SealedHeader) -> Result<Self> {
        let mut hasher = Sha256::new();
        let mut encoded = Vec::with_capacity(HEADER_LEN);
        header.write_to(&mut encoded)?;
        inner.write_all(&encoded)?;
        hasher.update(&encoded);
        Ok(Self { inner, hasher })
    }

    pub(crate) fn write_chunk(&mut self, last: bool, ciphertext: &[u8]) -> Result<()> {
        let len = u32::try_from(ciphertext.len()).context("sealed chunk is too large")?;
        let mut frame = Vec::with_capacity(5 + ciphertext.len());
        frame.push(u8::from(last));
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(ciphertext);
        self.inner.write_all(&frame)?;
        self.hasher.update(&frame);
        Ok(())
    }

    pub(crate) fn commitment(&self) -> [u8; 32] {
        self.hasher.clone().finalize().into()
    }
}

/// Reads one share from a file or device without reading past the share.
pub(crate) fn read_share_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut header = vec![0u8; SHARE_HEADER_LEN];
    reader.read_exact(&mut header).context("share is truncated")?;
    let body_len = u32::from_be_bytes(header[59..63].try_into().expect("4 bytes")) as usize;
    if body_len > 8192 {
        bail!("share body is too large");
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).context("share body is truncated")?;
    header.extend(body);
    Ok(header)
}

pub(crate) fn commitment_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::{SealedHeader, ShareRecord, FORMAT_VERSION};

    #[test]
    fn share_roundtrip_rejects_trailing_bytes() {
        let share = ShareRecord {
            index: 1,
            threshold: 3,
            count: 5,
            key_bytes: 32,
            group: [9u8; 16],
            commitment: [4u8; 32],
            password: true,
            body: b"body".to_vec(),
        };
        let encoded = share.encode().unwrap();
        let decoded = ShareRecord::decode(&encoded).unwrap();
        assert_eq!(decoded.index, 1);
        assert!(decoded.password);
        assert_eq!(decoded.body, b"body");
        let mut extra = encoded.clone();
        extra.push(0);
        assert!(ShareRecord::decode(&extra).is_err());
        assert_eq!(FORMAT_VERSION, 2);
    }

    #[test]
    fn sealed_header_rejects_a_share_magic() {
        let header = SealedHeader {
            threshold: 3,
            count: 5,
            key_bytes: 32,
            group: [1u8; 16],
            nonce_prefix: [2u8; 20],
        };
        let mut bytes = Vec::new();
        header.write_to(&mut bytes).unwrap();
        assert!(SealedHeader::read_from(&mut bytes.as_slice()).is_ok());
        assert!(SealedHeader::read_from(&mut &b"AGRH"[..]).is_err());
    }

    #[test]
    fn share_decoder_rejects_malformed_records() {
        let share = ShareRecord {
            index: 2,
            threshold: 3,
            count: 5,
            key_bytes: 32,
            group: [1u8; 16],
            commitment: [2u8; 32],
            password: false,
            body: vec![2, 9, 9],
        };
        let mut encoded = share.encode().unwrap();
        encoded[4] = 9;
        let err = ShareRecord::decode(&encoded).unwrap_err().to_string();
        assert!(err.contains("not this agree"), "{err}");

        encoded[4] = FORMAT_VERSION;
        encoded[58] = 0x02;
        assert!(ShareRecord::decode(&encoded)
            .unwrap_err()
            .to_string()
            .contains("unknown flags"));

        let err = ShareRecord::decode(b"AGRH").unwrap_err().to_string();
        assert!(err.contains("not an agree share"), "{err}");
        assert!(ShareRecord {
            index: 0,
            threshold: 1,
            count: 1,
            key_bytes: 32,
            group: [0u8; 16],
            commitment: [0u8; 32],
            password: false,
            body: vec![1],
        }
        .encode()
        .unwrap_err()
        .to_string()
        .contains("index 0"));

        let mut truncated = share.encode().unwrap();
        truncated.pop();
        assert!(ShareRecord::decode(&truncated).is_err());
    }

    #[test]
    fn read_share_bytes_stops_before_trailing_device_bytes() {
        let share = ShareRecord {
            index: 1,
            threshold: 1,
            count: 1,
            key_bytes: 32,
            group: [3u8; 16],
            commitment: [4u8; 32],
            password: false,
            body: vec![1, 2, 3],
        };
        let encoded = share.encode().unwrap();
        let mut stream = encoded.clone();
        stream.extend_from_slice(b"TRAILING-DEVICE-BYTES");
        let mut cursor = std::io::Cursor::new(stream);
        let read = super::read_share_bytes(&mut cursor).unwrap();
        assert_eq!(read, encoded);
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut cursor, &mut rest).unwrap();
        assert_eq!(rest, b"TRAILING-DEVICE-BYTES");

        let mut huge = encoded.clone();
        huge[59..63].copy_from_slice(&10_000u32.to_be_bytes());
        assert!(super::read_share_bytes(&mut huge.as_slice())
            .unwrap_err()
            .to_string()
            .contains("too large"));
    }

    #[test]
    fn sealed_reader_rejects_a_truncated_stream_and_an_oversized_chunk() {
        let header = SealedHeader {
            threshold: 2,
            count: 3,
            key_bytes: 32,
            group: [8u8; 16],
            nonce_prefix: [9u8; 20],
        };
        let mut bytes = Vec::new();
        header.write_to(&mut bytes).unwrap();
        assert!(super::SealedReader::open(bytes.as_slice()).is_ok());
        let mut short = bytes.clone();
        short.truncate(10);
        assert!(super::SealedReader::open(short.as_slice()).is_err());

        bytes.push(0);
        bytes.extend_from_slice(&(super::MAX_CHUNK_CIPHERTEXT as u32 + 1).to_be_bytes());
        let mut reader = super::SealedReader::open(bytes.as_slice()).unwrap();
        assert!(reader.next_chunk().unwrap_err().to_string().contains("too large"));
    }
}
