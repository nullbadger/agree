//! PIV management-key authentication for AES-192.
//!
//! `yubikey` 0.8.0 only authenticates a 3DES management key. Firmware 5.7 and
//! later ships an AES-192 key with the same 24 factory bytes. The algorithm
//! byte is read from the card, and a 3DES key stays on the crate path.

use {
    aes::cipher::{
        Block,
        BlockCipherDecrypt,
        BlockCipherEncrypt,
        Key,
        KeyInit,
    },
    anyhow::{
        bail,
        Context,
        Result,
    },
    rand_core::{
        OsRng,
        RngCore,
    },
    std::ffi::CStr,
};

const PIV_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];
const AES192: u8 = 0x0a;
const TDES: u8 = 0x03;

pub(crate) enum ManagementAlgorithm {
    Tdes,
    Aes192,
}

pub(crate) fn management_algorithm(serial: u32) -> Result<ManagementAlgorithm> {
    with_serial(serial, |card| {
        let metadata = transmit(card, &[0x00, 0xf7, 0x00, 0x9b, 0x00])?;
        let algorithm =
            algorithm_byte(&metadata).context("YubiKey management key metadata did not include an algorithm")?;
        match algorithm {
            | TDES => Ok(ManagementAlgorithm::Tdes),
            | AES192 => Ok(ManagementAlgorithm::Aes192),
            | other => bail!("unsupported YubiKey management key algorithm {other:02x}"),
        }
    })
}

pub(crate) fn object_exists(serial: Option<u32>, pin: &[u8], key: &[u8; 24], object: u32) -> Result<bool> {
    let serial = required_serial(serial)?;
    with_serial(serial, |card| {
        authenticate(card, pin, key)?;
        match fetch(card, object) {
            | Ok(_) => Ok(true),
            | Err(err) if is_missing(&err) => Ok(false),
            | Err(err) => Err(err),
        }
    })
}

pub(crate) fn write_object(
    serial: Option<u32>,
    pin: &[u8],
    key: &[u8; 24],
    object: u32,
    bytes: &[u8],
    force: bool,
) -> Result<()> {
    let serial = required_serial(serial)?;
    with_serial(serial, |card| {
        authenticate(card, pin, key)?;
        match fetch(card, object) {
            | Ok(_) if !force => {
                bail!("YubiKey object {object:06x} already exists. Use --force to overwrite it.");
            },
            | Ok(_) => {},
            | Err(err) if is_missing(&err) || force => {},
            | Err(err) => {
                return Err(err).context(format!("Failed to read YubiKey object {object:06x} before write"));
            },
        }
        save(card, object, bytes).with_context(|| format!("Failed to write YubiKey object {object:06x}"))
    })
}

fn required_serial(serial: Option<u32>) -> Result<u32> {
    serial.context("internal error: AES-192 YubiKey session has no serial")
}

fn with_serial<T>(serial: u32, body: impl FnOnce(&pcsc::Card) -> Result<T>) -> Result<T> {
    let context = pcsc::Context::establish(pcsc::Scope::User).context("Failed to open PC/SC")?;
    let mut names = vec![0u8; context.list_readers_len().context("Failed to list YubiKey readers")?];
    let readers = context
        .list_readers(&mut names)
        .context("Failed to list YubiKey readers")?;
    for reader in readers {
        if reader_serial(&context, reader)? != Some(serial) {
            continue;
        }
        let card = context
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .with_context(|| format!("Failed to open YubiKey {serial}"))?;
        select_piv(&card)?;
        return body(&card);
    }
    bail!("Failed to open YubiKey {serial}")
}

fn reader_serial(context: &pcsc::Context, reader: &CStr) -> Result<Option<u32>> {
    let Ok(card) = context.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY) else {
        return Ok(None);
    };
    if select_piv(&card).is_err() {
        return Ok(None);
    }
    let Ok(response) = transmit(&card, &[0x00, 0xf8, 0x00, 0x00, 0x00]) else {
        return Ok(None);
    };
    if status_word(&response) != 0x9000 || response.len() < 6 {
        return Ok(None);
    }
    let Ok(bytes) = response[..4].try_into() else {
        return Ok(None);
    };
    Ok(Some(u32::from_be_bytes(bytes)))
}

fn select_piv(card: &pcsc::Card) -> Result<()> {
    let mut apdu = vec![0x00, 0xa4, 0x04, 0x00, PIV_AID.len() as u8];
    apdu.extend_from_slice(&PIV_AID);
    status(&transmit(card, &apdu)?).context("Failed to select the PIV application")
}

fn authenticate(card: &pcsc::Card, pin: &[u8], key: &[u8; 24]) -> Result<()> {
    verify_pin(card, pin)?;
    let witness = transmit(card, &[0x00, 0x87, AES192, 0x9b, 0x04, 0x7c, 0x02, 0x80, 0x00])?;
    status(&witness).context("YubiKey management key authentication failed")?;
    let challenge = witness_bytes(&witness).context("YubiKey management key authentication failed")?;
    let opened = decrypt_block(key, challenge);
    let mut ours = [0u8; 16];
    OsRng.fill_bytes(&mut ours);
    let mut body = vec![0x7c, 0x24, 0x80, 0x10];
    body.extend_from_slice(&opened);
    body.extend_from_slice(&[0x81, 0x10]);
    body.extend_from_slice(&ours);
    let mut apdu = vec![0x00, 0x87, AES192, 0x9b, body.len() as u8];
    apdu.extend_from_slice(&body);
    let response = transmit(card, &apdu)?;
    status(&response).context("YubiKey management key authentication failed")?;
    let card_bytes = response_bytes(&response).context("YubiKey management key authentication failed")?;
    if card_bytes != encrypt_block(key, &ours) {
        bail!("YubiKey management key authentication failed");
    }
    Ok(())
}

fn verify_pin(card: &pcsc::Card, pin: &[u8]) -> Result<()> {
    let mut padded = [0xffu8; 8];
    padded[..pin.len()].copy_from_slice(pin);
    let mut apdu = vec![0x00, 0x20, 0x00, 0x80, 0x08];
    apdu.extend_from_slice(&padded);
    let response = transmit(card, &apdu)?;
    match status_word(&response) {
        | 0x9000 => Ok(()),
        | 0x6983 => Err(super::pin_failure(yubikey::Error::WrongPin { tries: 0 })),
        | word if word & 0xfff0 == 0x63c0 => {
            Err(super::pin_failure(yubikey::Error::WrongPin {
                tries: (word & 0x000f) as u8,
            }))
        },
        | _ => bail!("YubiKey PIN verification failed"),
    }
}

fn fetch(card: &pcsc::Card, object: u32) -> Result<Vec<u8>> {
    let header = object_header(object);
    let mut apdu = vec![0x00, 0xcb, 0x3f, 0xff, header.len() as u8];
    apdu.extend_from_slice(&header);
    let response = transmit(card, &apdu)?;
    if status_word(&response) == 0x6a82 {
        bail!("YubiKey object {object:06x} not found");
    }
    status(&response).with_context(|| format!("Failed to read YubiKey object {object:06x}"))?;
    tlv_value(&response[..response.len() - 2], 0x53)
        .with_context(|| format!("Failed to read YubiKey object {object:06x}"))
}

fn save(card: &pcsc::Card, object: u32, bytes: &[u8]) -> Result<()> {
    let mut data = object_header(object);
    data.push(0x53);
    data.push(u8::try_from(bytes.len()).context("YubiKey object is too large for one APDU")?);
    data.extend_from_slice(bytes);
    let mut apdu = vec![0x00, 0xdb, 0x3f, 0xff, data.len() as u8];
    apdu.extend_from_slice(&data);
    status(&transmit(card, &apdu)?).context("YubiKey management key authentication failed")
}

fn transmit(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = [0u8; 512];
    let mut response = card
        .transmit(apdu, &mut buf)
        .context("Failed to talk to the YubiKey")?
        .to_vec();
    while response.len() >= 2 && response[response.len() - 2] == 0x61 {
        let le = response[response.len() - 1];
        response.truncate(response.len() - 2);
        let get = [0x00, 0xc0, 0x00, 0x00, le];
        let more = card.transmit(&get, &mut buf).context("Failed to talk to the YubiKey")?;
        response.extend_from_slice(more);
    }
    if response.len() < 2 {
        bail!("YubiKey returned a short response");
    }
    Ok(response)
}

fn is_missing(err: &anyhow::Error) -> bool {
    err.to_string().contains("not found")
}

fn algorithm_byte(response: &[u8]) -> Option<u8> {
    let body = response.get(..response.len().saturating_sub(2))?;
    let mut index = 0;
    while index + 2 < body.len() {
        let tag = body[index];
        let len = body[index + 1] as usize;
        if index + 2 + len > body.len() {
            return None;
        }
        if tag == 0x01 && len == 1 {
            return Some(body[index + 2]);
        }
        index += 2 + len;
    }
    None
}

fn object_header(object: u32) -> Vec<u8> {
    vec![
        0x5c,
        0x03,
        ((object >> 16) & 0xff) as u8,
        ((object >> 8) & 0xff) as u8,
        (object & 0xff) as u8,
    ]
}

fn tlv_value(body: &[u8], tag: u8) -> Result<Vec<u8>> {
    if body.len() < 2 || body[0] != tag {
        bail!("YubiKey object was not a data TLV");
    }
    let len = body[1] as usize;
    if body.len() < 2 + len {
        bail!("YubiKey object was truncated");
    }
    Ok(body[2..2 + len].to_vec())
}

fn witness_bytes(response: &[u8]) -> Result<&[u8]> {
    let body = &response[..response.len() - 2];
    if body.len() < 20 || body[0] != 0x7c || body[2] != 0x80 || body[3] != 16 {
        bail!("unexpected management key witness");
    }
    Ok(&body[4..20])
}

fn response_bytes(response: &[u8]) -> Result<[u8; 16]> {
    let body = &response[..response.len() - 2];
    if body.len() < 20 || body[2] != 0x82 || body[3] != 16 {
        bail!("unexpected management key response");
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&body[4..20]);
    Ok(out)
}

fn decrypt_block(key: &[u8; 24], block: &[u8]) -> [u8; 16] {
    let cipher = aes::Aes192::new(&Key::<aes::Aes192>::from(*key));
    let mut output = Block::<aes::Aes192>::try_from(block).expect("AES block is 16 bytes");
    cipher.decrypt_block(&mut output);
    output.into()
}

fn encrypt_block(key: &[u8; 24], block: &[u8]) -> [u8; 16] {
    let cipher = aes::Aes192::new(&Key::<aes::Aes192>::from(*key));
    let mut output = Block::<aes::Aes192>::try_from(block).expect("AES block is 16 bytes");
    cipher.encrypt_block(&mut output);
    output.into()
}

fn status(response: &[u8]) -> Result<()> {
    match status_word(response) {
        | 0x9000 => Ok(()),
        | word => bail!("YubiKey status {word:04x}"),
    }
}

fn status_word(response: &[u8]) -> u16 {
    let n = response.len();
    u16::from_be_bytes([response[n - 2], response[n - 1]])
}

#[cfg(test)]
mod tests {
    use super::{
        algorithm_byte,
        decrypt_block,
        encrypt_block,
    };

    #[test]
    fn reads_the_algorithm_from_management_key_metadata() {
        let response = [0x01, 0x01, 0x0a, 0x02, 0x02, 0x00, 0x01, 0x05, 0x01, 0x01, 0x90, 0x00];
        assert_eq!(algorithm_byte(&response), Some(0x0a));
    }

    #[test]
    fn aes192_block_roundtrip() {
        let key = [1u8, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let block = [9u8; 16];
        assert_eq!(decrypt_block(&key, &encrypt_block(&key, &block)), block);
    }
}
