use dexios_core::header::{Header, HeaderType, HEADER_VERSION ,HeaderVersion};
use dexios_core::key::{gen_salt};
use dexios_core::primitives::{Algorithm, gen_nonce};
use dexios_core::primitives::Mode;
use dexios_core::key::argon2id_hash;
use std::io::Write;
use std::fs::File;
use anyhow::Context;
use anyhow::Result;
use dexios_core::header;
use dexios_core::protected::Protected;

use dexios_core::stream::{EncryptionStreams, Ui};
use dexios_core::stream::DecryptionStreams;

pub fn encrypt<>(
    input: &mut File,
    output: &mut File,
    password: &String,
    ui: &Box<dyn Ui>,
    algorithm: Algorithm,
) -> Result<()> {

    let filesize= input.metadata().unwrap().len();


    let salt = gen_salt();
    let nonce = gen_nonce(algorithm, Mode::StreamMode);

    let passvec: Vec<u8> = password.as_bytes().to_vec();
    let raw_key = argon2id_hash(Protected::new(passvec), &salt, &HEADER_VERSION)?;

    let streams = EncryptionStreams::initialize(raw_key, &nonce.as_slice(), algorithm)?;

    let header_type=HeaderType {
        version: HeaderVersion::V3,
        algorithm,
        mode: Mode::StreamMode
    };

    let header = Header {
        header_type,
        nonce,
        salt,
    };

    header.write(output)?;
    let aad = header.serialize()?;
    streams.encrypt_file(input, output, &aad, filesize, ui)?;
    output.flush().context("Unable to flush the output file")?;
    Ok(())
}

pub fn decrypt<>(
    input: &mut File,
    output: &mut File,
    password: &String,
    ui: &Box<dyn Ui>,
) -> Result<()> {

    let filesize= input.metadata().unwrap().len();

    let deserialized_header= header::Header::deserialize(input)?;

    let passvec: Vec<u8> = password.as_bytes().to_vec();
    let raw_key = argon2id_hash(Protected::new(passvec), &deserialized_header.0.salt, &deserialized_header.0.header_type.version)?;
    let streams = DecryptionStreams::initialize(raw_key, &deserialized_header.0.nonce, deserialized_header.0.header_type.algorithm)?;

    let aad = deserialized_header.0.serialize()?;
    streams.decrypt_file(input, output, &aad, filesize, ui)?;
    output.flush().context("Unable to flush the output file")?;

    Ok(())
}
