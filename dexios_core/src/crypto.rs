use crate::keygen::*;
use crate::constants::*;
use crate::{Algorithm, DecryptStreamCiphers, EncryptStreamCiphers, Ui};
use crate::header::{CipherMode, create_aad, Header, HeaderType};
use crate::secret::*;
use rand::{Rng, SeedableRng};
use aes_gcm::{Aes256Gcm};
use chacha20poly1305::XChaCha20Poly1305;
use aead::{NewAead, Payload};
use std::{io::{Read, Write}};
use std::fs::File;
use aead::stream::{DecryptorLE31, EncryptorLE31};
use deoxys::DeoxysII256;
use rand::prelude::StdRng;
use anyhow::anyhow;
use anyhow::Result;

pub fn init_encryption_stream(
    password: &Secret<String>,
    header_type: HeaderType,
) -> Result<(EncryptStreamCiphers, Header)> {
    let salt = gen_salt();
    let key = argon2_hash(password, &salt, &header_type.header_version)?;

    println!("{:?}",key.expose());

    match header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 8]>();

            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::Aes256Gcm(Box::new(stream)),
                header,
            ))
        }
        Algorithm::XChaCha20Poly1305 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 20]>();

            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::XChaCha(Box::new(stream)),
                header,
            ))
        }
        Algorithm::DeoxysII256 => {
            let nonce_bytes = StdRng::from_entropy().gen::<[u8; 11]>();

            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let header = Header {
                header_type,
                nonce: nonce_bytes.to_vec(),
                salt,
            };

            let stream = EncryptorLE31::from_aead(cipher, nonce_bytes.as_slice().into());
            Ok((
                EncryptStreamCiphers::DeoxysII(Box::new(stream)),
                header,
            ))
        }
    }
}

// this function hashes the provided key, and then initialises the stream ciphers
// it's used for decrypt/stream mode and is the central place for managing streams for decryption
pub fn init_decryption_stream(
    password: &Secret<String>,
    header: Header,
) -> Result<DecryptStreamCiphers> {
    let key = argon2_hash(password, &header.salt, &header.header_type.header_version)?;

    match header.header_type.algorithm {
        Algorithm::Aes256Gcm => {
            let cipher = match Aes256Gcm::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::Aes256Gcm(Box::new(stream)))
        }
        Algorithm::XChaCha20Poly1305 => {
            let cipher = match XChaCha20Poly1305::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::XChaCha(Box::new(stream)))
        }
        Algorithm::DeoxysII256 => {
            let cipher = match DeoxysII256::new_from_slice(key.expose()) {
                Ok(cipher) => cipher,
                Err(_) => return Err(anyhow!("Unable to create cipher with argon2id hashed key.")),
            };

            let stream = DecryptorLE31::from_aead(cipher, header.nonce.as_slice().into());
            Ok(DecryptStreamCiphers::DeoxysII(Box::new(stream)))
        }
    }
}

pub fn encrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: u64,
    algorithm: Algorithm,
) -> Result<()> {

    let header_type = HeaderType {
        header_version: VERSION,
        cipher_mode: CipherMode::StreamMode,
        algorithm,
    };

    let (mut streams, header) = init_encryption_stream(password, header_type).unwrap();
    crate::header::write_to_file(output, &header)?;
    let aad = create_aad(&header);

    let mut buffer = [0u8; BLOCK_SIZE];
    let mut total_bytes_read = 0;

    loop {
        let read_count = input.read(&mut buffer).unwrap();
        total_bytes_read += read_count;
        if read_count == BLOCK_SIZE {
            // aad is just empty bytes normally
            // create_aad returns empty bytes if the header isn't V3+
            // this means we don't need to do anything special in regards to older versions
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let encrypted_data = match streams.encrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt the data")),
            };

                output.write_all(&encrypted_data).unwrap();

        } else {
            // if we read something less than MSGLEN, and have hit the end of the file
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };

            let encrypted_data = match streams.encrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to encrypt the data")),
            };

            output.write_all(&encrypted_data).unwrap();
            break;
        }
        // progress
        let percentage = (((total_bytes_read as f32) / (filesize as f32)) * 100.) as i32;
        ui.output(percentage);
    }
    output.flush().unwrap();
    Ok(())
}

pub fn decrypt<>(
    input: &mut File,
    output: &mut File,
    password: &Secret<String>,
    ui: &Box<dyn Ui>,
    filesize: u64,
) -> Result<()> {

    let (header, aad)=crate::header::read_from_file(input)?;

    let mut streams = init_decryption_stream(password, header)?;
    let mut buffer = [0u8; BLOCK_SIZE + TAGLEN]; // TAGLEN is the length of the AEAD tag

    let mut total_bytes_read = 0;

    loop {
        let read_count = input.read(&mut buffer)?;
        total_bytes_read += read_count;
        if read_count == (BLOCK_SIZE + TAGLEN) {
            let payload = Payload {
                aad: &aad,
                msg: buffer.as_ref(),
            };
            let decrypted_data = match streams.decrypt_next(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")),
            };
            output.write_all(&decrypted_data).unwrap();

        } else {
            // if we read something less than BLOCK_SIZE+16, and have hit the end of the file
            let payload = Payload {
                aad: &aad,
                msg: &buffer[..read_count],
            };
            let decrypted_data = match streams.decrypt_last(payload) {
                Ok(bytes) => bytes,
                Err(_) => return Err(anyhow!("Unable to decrypt the data. This means either: you're using the wrong key, this isn't an encrypted file, or the header has been tampered with.")),
            };
            output.write_all(&decrypted_data).unwrap();
            output.flush().unwrap();
            break;
        }
        // progress
        let percentage = (((total_bytes_read as f32) / (filesize as f32)) * 100.) as i32;
        ui.output(percentage);
    }
    Ok(())
}
