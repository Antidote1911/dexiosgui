#![allow(dead_code)]
use crate::header::HeaderVersion;

pub const APP_NAME: &str = env!("CARGO_PKG_NAME");
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

//// Crypto constants
pub const BLOCK_SIZE: usize = 1_048_576; // 1024*1024 bytes
pub const SALTLEN: usize = 16;
pub const KEYLEN: usize = 32;
pub const TAGLEN: usize = 16;

pub const VERSION: HeaderVersion = HeaderVersion::V3;
