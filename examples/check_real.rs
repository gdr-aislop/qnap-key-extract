//! Differential test harness: calls the REAL QNAP `Keyfile_to_Keystring`
//! (from libuLinux_Storage.so via dlopen) on generated .key blobs and
//! compares the result with this crate's pure-Rust decoder.
//!
//! Usage:
//!   QNAP_LIB=/path/to/libuLinux_Storage.so \
//!   LD_LIBRARY_PATH=<fw libs> cargo run --release --example check_real

use std::env;
use std::ffi::{CStr, CString};
use std::fs;
use std::os::raw::{c_char, c_int};

extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut std::os::raw::c_void;
    fn dlsym(handle: *mut std::os::raw::c_void, symbol: *const c_char)
        -> *mut std::os::raw::c_void;
}

// int Keyfile_to_Keystring(const char *file, char *out, int outlen)
type KeyfileToKeystring = unsafe extern "C" fn(*const c_char, *mut c_char, c_int) -> c_int;

fn main() {
    let lib = env::var("QNAP_LIB").expect("set QNAP_LIB to libuLinux_Storage.so path");
    let lib_c = CString::new(lib.clone()).unwrap();
    let sym_c = CString::new("Keyfile_to_Keystring").unwrap();

    unsafe {
        let h = dlopen(lib_c.as_ptr(), 2 /* RTLD_NOW */);
        if h.is_null() {
            eprintln!("dlopen failed");
            std::process::exit(2);
        }
        let f: KeyfileToKeystring = std::mem::transmute(dlsym(h, sym_c.as_ptr()));
        if f as usize == 0 {
            eprintln!("dlsym failed");
            std::process::exit(2);
        }

        let tmp = std::env::temp_dir().join("qnap_diff_test.key");
        let mut pass = 0;
        let mut fail = 0;

        // 256-byte blobs hold at most 28 key chars; 512-byte blobs up to 64.
        let keys: Vec<Vec<u8>> = vec![
            b"ShortPw1!".to_vec(),
            b"ExactlyTwentyChars..".to_vec(),
            b"28chars-max-for-256blob-yes".to_vec(), // exactly 28 chars
            b"password with spaces".to_vec(),
            b"P@$$w0rd!#%&*()".to_vec(),
        ];

        for &(_fmt, size, count_off) in &[(256usize, 256usize, 248usize), (512, 600, 504)] {
            for key in &keys {
                // plain variant (flag=0) - what real .key files use
                let mut blob = vec![0x5Au8; size];
                for (i, &b) in key.iter().enumerate() {
                    blob[8 + 9 * i] = b;
                }
                blob[count_off] = b'0' + (key.len() / 10) as u8;
                blob[count_off + 1] = b'0' + (key.len() % 10) as u8;
                fs::write(&tmp, &blob).unwrap();

                let path_c = CString::new(tmp.to_str().unwrap()).unwrap();
                let mut out = [0u8; 512];
                let ret = f(path_c.as_ptr(), out.as_mut_ptr() as *mut c_char, 512);
                let real = CStr::from_bytes_until_nul(&out)
                    .unwrap()
                    .to_bytes()
                    .to_vec();

                let mine = qnap_key_extract::keyfile::decode_keyfile(&blob)
                    .map(|c| c[0].key.clone())
                    .unwrap_or_default();

                let ok = ret == 0 && real == mine;
                if ok {
                    pass += 1;
                } else {
                    fail += 1;
                    eprintln!(
                        "MISMATCH fmt={size} key={:?}: real(ret={ret})={:?} mine={:?}",
                        String::from_utf8_lossy(key),
                        String::from_utf8_lossy(&real),
                        String::from_utf8_lossy(&mine)
                    );
                }
            }
        }

        println!("differential decode test vs real library: {pass} passed, {fail} failed");
        let _ = fs::remove_file(&tmp);
        std::process::exit(if fail == 0 { 0 } else { 1 });
    }
}
