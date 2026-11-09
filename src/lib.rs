//! qnap-key-extract library: recover LUKS passphrases for QNAP QTS
//! encrypted volumes from .key files, DOM images, or plain passwords.
//!
//! All format knowledge was reverse engineered from QTS 5.2
//! `libuLinux_Storage.so` and cross-checked against public research.

pub mod dom;
pub mod keyfile;
pub mod md5crypt;
