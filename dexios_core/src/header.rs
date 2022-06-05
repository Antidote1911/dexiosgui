use std::fs::File;
use std::io::{Read, Write};
use anyhow::{Context, Result};
use crate::{Algorithm, SALTLEN};
use blake3::Hasher;

#[derive(PartialEq, Eq)]
pub enum CipherMode {
    // could do with a better name
    MemoryMode,
    StreamMode,
}


#[derive(PartialEq)]
pub enum HeaderVersion {
    V1,
    V2,
    V3,
}

// the information needed to easily serialize a header
pub struct HeaderType {
    pub header_version: HeaderVersion,
    pub cipher_mode: CipherMode,
    pub algorithm: Algorithm,
}

// the data used returned after reading/deserialising a header
pub struct Header {
    pub header_type: HeaderType,
    pub nonce: Vec<u8>,
    pub salt: [u8; SALTLEN],
}

// this writes a header to a file
// it handles padding and serialising the specific information
// it ensures the buffer is left at 64 bytes, so other functions can write the data without further hassle
pub fn write_to_file(file: &mut File, header: &Header) -> Result<()> {
    let nonce_len = calc_nonce_len(&header.header_type);

    match &header.header_type.header_version {
        HeaderVersion::V1 | HeaderVersion::V3 => {
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            file.write_all(&version_info)
                .context("Unable to write version to header")?;
            file.write_all(&algorithm_info)
                .context("Unable to write algorithm to header")?;
            file.write_all(&mode_info)
                .context("Unable to write encryption mode to header")?; // 6 bytes total
            file.write_all(&header.salt)
                .context("Unable to write salt to header")?; // 22 bytes total
            file.write_all(&[0; 16])
                .context("Unable to write empty bytes to header")?; // 38 bytes total (26 remaining)
            file.write_all(&header.nonce)
                .context("Unable to write nonce to header")?; // (26 - nonce_len remaining)
            file.write_all(&padding)
                .context("Unable to write final padding to header")?; // this has reached the 64 bytes
        }
        HeaderVersion::V2 => {
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            file.write_all(&version_info)
                .context("Unable to write version to header")?;
            file.write_all(&algorithm_info)
                .context("Unable to write algorithm to header")?;
            file.write_all(&mode_info)
                .context("Unable to write encryption mode to header")?; // 6 bytes total
            file.write_all(&header.salt)
                .context("Unable to write salt to header")?; // 22 bytes total
            file.write_all(&header.nonce)
                .context("Unable to write nonce to header")?; // (26 - nonce len)
            file.write_all(&padding)
                .context("Unable to write final padding to header")?; // this has reached 48 bytes
            file.write_all(&[0u8; 16])
                .context("Unable to write signature to header")?; // signature
        }
    }

    Ok(())
}

// this takes an input file, and gets all of the data necessary from the header of the file
// it ensures that the buffer starts at 64 bytes, so that other functions can just read encrypted data immediately
pub fn read_from_file(file: &mut File) -> Result<(Header, Vec<u8>)> {
    let mut version_info = [0u8; 2];
    let mut algorithm_info = [0u8; 2];
    let mut mode_info = [0u8; 2];
    let mut salt = [0u8; SALTLEN];

    file.read_exact(&mut version_info)
        .context("Unable to read version from header")?;
    file.read_exact(&mut algorithm_info)
        .context("Unable to read algorithm from header")?;
    file.read_exact(&mut mode_info)
        .context("Unable to read encryption mode from header")?;

    let header_info = deserialize(version_info, algorithm_info, mode_info)?;
    match header_info.header_version {
        HeaderVersion::V1 => {
            //warn!("You are using an older version of the Dexios header standard, please re-encrypt your files at your earliest convenience");
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];

            file.read_exact(&mut salt)
                .context("Unable to read salt from header")?;
            file.read_exact(&mut [0; 16])
                .context("Unable to read empty bytes from header")?; // read and subsequently discard the next 16 bytes
            file.read_exact(&mut nonce)
                .context("Unable to read nonce from header")?;
            file.read_exact(&mut vec![0u8; 26 - nonce_len])
                .context("Unable to read final padding from header")?; // read and discard the final padding

            let header = Header {
                header_type: header_info,
                nonce,
                salt,
            };

            let aad = get_aad(&header, None, None);

            Ok((header, aad))
        }
        HeaderVersion::V2 => {
            //warn!("You are using an older version of the Dexios header standard, please re-encrypt your files at your earliest convenience");
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];

            file.read_exact(&mut salt)
                .context("Unable to read salt from header")?;
            file.read_exact(&mut nonce)
                .context("Unable to read nonce from header")?;
            file.read_exact(&mut vec![0u8; 26 - nonce_len])
                .context("Unable to read final padding from header")?; // read and discard the padding
            file.read_exact(&mut [0u8; 16])
                .context("Unable to read signature from header")?; // read signature

            let header = Header {
                header_type: header_info,
                nonce,
                salt,
            };

            let aad = get_aad(&header, None, None);

            Ok((header, aad))
        }
        HeaderVersion::V3 => {
            let nonce_len = calc_nonce_len(&header_info);
            let mut nonce = vec![0u8; nonce_len];
            let mut padding1 = [0u8; 16];
            let mut padding2 = vec![0u8; 26 - nonce_len];

            file.read_exact(&mut salt)
                .context("Unable to read salt from header")?;
            file.read_exact(&mut padding1)
                .context("Unable to read empty bytes from header")?; // read and subsequently discard the next 16 bytes
            file.read_exact(&mut nonce)
                .context("Unable to read nonce from header")?;
            file.read_exact(&mut padding2)
                .context("Unable to read final padding from header")?; // read and discard the final padding

            let header = Header {
                header_type: header_info,
                nonce,
                salt,
            };

            let aad = get_aad(&header, Some(padding1), Some(padding2));

            Ok((header, aad))
        }
    }
}

// this calculates how long the nonce will be, based on the provided input
fn calc_nonce_len(header_info: &HeaderType) -> usize {
    let mut nonce_len = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => 24,
        Algorithm::Aes256Gcm => 12,
        Algorithm::DeoxysII256 => 15,
    };
    nonce_len -= 4; // the last 4 bytes are dynamic in streamLE mode
    nonce_len
}

// this takes information about the header, and serializes it into raw bytes
// this is the inverse of the deserialize function
fn serialize(header_info: &HeaderType) -> ([u8; 2], [u8; 2], [u8; 2]) {
    let version_info = match header_info.header_version {
        HeaderVersion::V1 => {
            let info: [u8; 2] = [0xDE, 0x01];
            info
        }
        HeaderVersion::V2 => {
            let info: [u8; 2] = [0xDE, 0x02];
            info
        }
        HeaderVersion::V3 => {
            let info: [u8; 2] = [0xDE, 0x03];
            info
        }
    };
    let algorithm_info = match header_info.algorithm {
        Algorithm::XChaCha20Poly1305 => {
            let info: [u8; 2] = [0x0E, 0x01];
            info
        }
        Algorithm::Aes256Gcm => {
            let info: [u8; 2] = [0x0E, 0x02];
            info
        }
        Algorithm::DeoxysII256 => {
            let info: [u8; 2] = [0x0E, 0x03];
            info
        }
    };

    let mode_info = match header_info.cipher_mode {
        CipherMode::StreamMode => {
            let info: [u8; 2] = [0x0C, 0x01];
            info
        }
        CipherMode::MemoryMode => {
            let info: [u8; 2] = [0x0C, 0x02];
            info
        }
    };

    (version_info, algorithm_info, mode_info)
}

// this is used for converting raw bytes from the header to enums that dexios can understand
// this involves the header version, encryption algorithm/mode, and possibly more in the future
fn deserialize(
    version_info: [u8; 2],
    algorithm_info: [u8; 2],
    mode_info: [u8; 2],
) -> Result<HeaderType> {
    let header_version = match version_info {
        [0xDE, 0x01] => HeaderVersion::V1,
        [0xDE, 0x02] => HeaderVersion::V2,
        [0xDE, 0x03] => HeaderVersion::V3,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    let algorithm = match algorithm_info {
        [0x0E, 0x01] => Algorithm::XChaCha20Poly1305,
        [0x0E, 0x02] => Algorithm::Aes256Gcm,
        [0x0E, 0x03] => Algorithm::DeoxysII256,
        _ => return Err(anyhow::anyhow!("Error getting encryption mode from header")),
    };

    let cipher_mode = match mode_info {
        [0x0C, 0x01] => CipherMode::StreamMode,
        [0x0C, 0x02] => CipherMode::MemoryMode,
        _ => return Err(anyhow::anyhow!("Error getting cipher mode from header")),
    };

    Ok(HeaderType {
        header_version,
        cipher_mode,
        algorithm,
    })
}


// this hashes a header with the salt, nonce, and info provided
pub fn _hash(hasher: &mut Hasher, header: &Header) {
    match &header.header_type.header_version {
        HeaderVersion::V1 | HeaderVersion::V3 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            hasher.update(&version_info);
            hasher.update(&algorithm_info);
            hasher.update(&mode_info);
            hasher.update(&header.salt);
            hasher.update(&[0; 16]);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
        HeaderVersion::V2 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let padding = vec![0u8; 26 - nonce_len];
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            hasher.update(&version_info);
            hasher.update(&algorithm_info);
            hasher.update(&mode_info);
            hasher.update(&header.salt);
            hasher.update(&header.nonce);
            hasher.update(&padding);
        }
    }
}


pub fn get_aad(header: &Header, padding1: Option<[u8; 16]>, padding2: Option<Vec<u8>>) -> Vec<u8> {
    match header.header_type.header_version {
        HeaderVersion::V3 => {
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            let mut header_bytes = version_info.to_vec();
            header_bytes.extend_from_slice(&mode_info);
            header_bytes.extend_from_slice(&algorithm_info);
            header_bytes.extend_from_slice(&header.salt);
            header_bytes.extend_from_slice(&padding1.unwrap());
            header_bytes.extend_from_slice(&header.nonce);
            header_bytes.extend_from_slice(&padding2.unwrap());
            header_bytes
        }
        _ => Vec::new(),
    }
}

pub fn create_aad(header: &Header) -> Vec<u8> {
    match header.header_type.header_version {
        HeaderVersion::V3 => {
            let nonce_len = calc_nonce_len(&header.header_type);
            let (version_info, algorithm_info, mode_info) = serialize(&header.header_type);

            let mut header_bytes = version_info.to_vec();
            header_bytes.extend_from_slice(&mode_info);
            header_bytes.extend_from_slice(&algorithm_info);
            header_bytes.extend_from_slice(&header.salt);
            header_bytes.extend_from_slice(&[0; 16]);
            header_bytes.extend_from_slice(&header.nonce);
            header_bytes.extend_from_slice(&vec![0; 26 - nonce_len]);
            header_bytes
        }
        _ => Vec::new(),
    }
}