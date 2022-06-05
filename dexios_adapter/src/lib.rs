use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr::null_mut;

use dexios_core::{get_version, main_routine, Config, Direction, Ui, Algorithm, Secret};
struct ProgressUpdater {
    output_func: extern "C" fn(i32),
}

impl Ui for ProgressUpdater {
    fn output(&self, percentage: i32) {
        (self.output_func)(percentage);
    }
}

#[no_mangle]
pub extern "C" fn makeConfig(
    direction: u8,
    algorithm: u8,
    password: *mut c_char,
    filename: *mut c_char,
    out_filename: *mut c_char,
    output_func: extern "C" fn(i32),
) -> *mut Config {
    let dir = match direction {
        0 => Direction::Encrypt,
        1 => Direction::Decrypt,
        _ => panic!("received invalid direction enum from c++"),
    };
    let algo = match algorithm {
        0 => Algorithm::XChaCha20Poly1305,
        1 => Algorithm::Aes256Gcm,
        2 => Algorithm::DeoxysII256,
        _ => panic!("received invalid algorithm enum from c++"),
    };

    let p = match c_to_rust_string(password) {
        Ok(s) => s,
        Err(_) => return null_mut(),
    };
    let f = match c_to_rust_string(filename) {
        Ok(s) => s,
        Err(_) => return null_mut(),
    };
    let o = match c_to_rust_string(out_filename) {
        Ok(s) => s,
        Err(_) => return null_mut(),
    };
    let ui = Box::new(ProgressUpdater { output_func });
    Box::into_raw(Box::new(Config::new(dir,algo ,Secret::new(p), Some(f), Some(o), ui)))
}

#[no_mangle]
pub extern "C" fn get_version2() -> *mut c_char {
    rust_to_c_string(get_version().to_string())
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[no_mangle]
pub unsafe extern "C" fn start(ptr: *mut Config) -> *mut c_char {
    let config = { &mut *ptr };
    let msg = match main_routine(config) {
        Ok(duration) => match config.direction {
            Direction::Encrypt => format!(
                "Success! File {} has been encrypted in {} s with {}",
                config.out_file.as_ref().unwrap(),duration,config.algorithm
            ),
            Direction::Decrypt => format!(
                "Success! File {} has been decrypted in {} s",
                config.out_file.as_ref().unwrap(),duration
            ),
        },
        Err(e) => format!("{:?}", e),
    };
    rust_to_c_string(msg)
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[no_mangle]
pub unsafe extern "C" fn destroyConfig(ptr: *mut Config) {
    if ptr.is_null() {
        drop(Box::from_raw(&mut *ptr));
    }
}

/// # Safety
///
/// This function should not be called before the horsemen are ready.
#[no_mangle]
pub unsafe extern "C" fn destroyCString(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

fn rust_to_c_string(s: String) -> *mut c_char {
    CString::new(s).unwrap().into_raw()
}

fn c_to_rust_string(ptr: *mut c_char) -> Result<String, String> {
    let c_str: &CStr = unsafe { CStr::from_ptr(ptr) };
    let res = c_str
        .to_str()
        .map_err(|_| "Could not convert C string to Rust string".to_string())?
        .to_string();
    Ok(res)
}
