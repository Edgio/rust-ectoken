#![deny(missing_docs)]
//! This module could be used to encrypt/decrypt tokens

use aes_gcm::aead::{generic_array::typenum::U32, generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::error;
use std::fmt;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Real derived key
#[derive(Clone, PartialEq)]
pub struct Ec3Key(pub GenericArray<u8, U32>);

impl Ec3Key {
    /// Create a new key that could be used for encryption/decryption afterwards
    pub fn new(key: &str) -> Self {
        Self::new_raw(key.as_bytes())
    }

    /// Create a new key from raw string
    pub fn new_raw(key: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(key);
        Self(hasher.finalize())
    }

    /// Encrypts token with key
    pub fn encrypt(&self, token: &str) -> String {
        let nonce = rand::thread_rng().gen::<[u8; NONCE_LEN]>();
        let nonce = GenericArray::from_slice(&nonce);
        let cipher = Aes256Gcm::new(&self.0);

        let mut ciphertext = cipher
            .encrypt(nonce, token.as_bytes())
            .expect("encryption failure!");

        let mut encrypted: Vec<u8> = Vec::from(nonce.as_slice());
        encrypted.append(&mut ciphertext);

        base64::encode_config(&encrypted, base64::URL_SAFE_NO_PAD)
    }

    /// Decrypt given token with already derived key
    pub fn decrypt(&self, token: &str) -> Result<String, DecryptionError> {
        let token = base64::decode_config(token, base64::URL_SAFE_NO_PAD)?;

        if token.len() < (NONCE_LEN + TAG_LEN) as usize {
            return Err(DecryptionError::IOError("invalid input length"));
        }

        let cipher = Aes256Gcm::new(&self.0);
        let nonce = GenericArray::from_slice(&token[0..NONCE_LEN]);

        let ciphertext = &token[NONCE_LEN..];

        let plaintext = match cipher.decrypt(nonce, ciphertext) {
            Ok(text) => text,
            Err(_) => return Err(DecryptionError::IOError("decryption failed")),
        };

        let s = String::from_utf8(plaintext)?;
        Ok(s)
    }
}

/// EncryptV3 encrypts the given content using the supplied key.
///
/// ```
/// let input = "ec_expire=1257642471&ec_secure=33";
///
/// let encrypted = ectoken::encrypt_v3("testkey123", input);
/// println!("{}", encrypted);
/// # let decrypted = ectoken::decrypt_v3("testkey123", &encrypted).unwrap();
///
/// # assert_eq!(input, decrypted);
/// ```
pub fn encrypt_v3(key: &str, token: &str) -> String {
    let key = Ec3Key::new(key);

    key.encrypt(token)
}

/// Decrypts the given token using the supplied key. On success,
/// returns the decrypted content. If the token is invalid or
/// can not be decrypted, returns DecryptionError.
///
/// ```
/// let decrypted = ectoken::decrypt_v3("testkey123", "bs4W7wyy0OjyBQMhAaahSVo2sG4gKEzuOegBf9kI-ZzG8Gz4FQuFud2ndvmuXkReeRnKFYXTJ7q5ynniGw").unwrap();
///
/// assert_eq!("ec_expire=1257642471&ec_secure=33", decrypted);
/// ```
pub fn decrypt_v3(key: &str, token: &str) -> Result<String, DecryptionError> {
    let key = Ec3Key::new(key);

    key.decrypt(token)
}

/// Errors that can occur while decoding.
#[derive(Debug)]
pub enum DecryptionError {
    /// An invalid base64 string was found in the input.
    InvalidBase64(base64::DecodeError),
    /// An invalid UTF8 string was found once decrypted.
    InvalidUTF8(std::string::FromUtf8Error),
    /// An invalid input/output was
    IOError(&'static str),
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecryptionError::InvalidBase64(_) => write!(f, "Invalid base64."),
            DecryptionError::InvalidUTF8(_) => write!(f, "Invalid UTF8 string decrypted."),
            DecryptionError::IOError(description) => {
                write!(f, "Input/Output error: {}", description)
            }
        }
    }
}

impl error::Error for DecryptionError {
    fn description(&self) -> &str {
        match *self {
            DecryptionError::InvalidBase64(_) => "invalid base64",
            DecryptionError::InvalidUTF8(_) => "invalid UTF8 string decrypted",
            DecryptionError::IOError(_) => "input/output error",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            DecryptionError::InvalidBase64(ref previous) => Some(previous),
            DecryptionError::InvalidUTF8(ref previous) => Some(previous),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for DecryptionError {
    fn from(err: base64::DecodeError) -> DecryptionError {
        DecryptionError::InvalidBase64(err)
    }
}

impl From<std::string::FromUtf8Error> for DecryptionError {
    fn from(err: std::string::FromUtf8Error) -> DecryptionError {
        DecryptionError::InvalidUTF8(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_decodes_properly() {
        let key = "mykey";
        let msg = "hello world";
        let encrypted = encrypt_v3(&key, &msg);
        assert_eq!(msg, decrypt_v3(&key, &encrypted).expect("decrypt failed"));
    }

    #[test]
    fn it_returns_err_on_invalid_base64_string() {
        let decrypted = decrypt_v3(
            "testkey123",
            "af0c6acf7906cd500aee63a4dd2e97ddcb0142601cf83aa9d622289718c4c85413",
        );

        assert!(
            decrypted.is_err(),
            "decryption should be an Error with invalid base64 encoded string"
        );
    }

    #[test]
    fn it_returns_err_on_invalid_length() {
        let decrypted = decrypt_v3("testkey123", "bs4W7wyy");

        assert!(
            decrypted.is_err(),
            "decryption should be an Error with invalid length encoded string"
        );
    }
}
