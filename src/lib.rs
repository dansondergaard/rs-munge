extern crate libc;
extern crate munge_sys;

use std::ffi::{CStr, CString};
use std::fmt;

use munge_sys::{munge_decode, munge_encode, munge_strerror, MUNGE_SUCCESS};

#[derive(Debug)]
pub struct DecodedMessage {
    uid: u32,
    gid: u32,
    payload: Option<String>,
}

impl DecodedMessage {
    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn payload(&self) -> &Option<String> {
        &self.payload
    }
}

#[derive(Debug)]
pub enum MungeError {
    Snafu,
    BadArg,
    BadLength,
    Overflow,
    NoMemory,
    Socket,
    Timeout,
    BadCred,
    BadVersion,
    BadCipher,
    BadMac,
    BadZip,
    BadRealm,
    CredInvalid,
    CredExpired,
    CredRewound,
    CredReplayed,
    CredUnauthorized,
}

impl MungeError {
    fn to_string(&self) -> String {
        unsafe {
            let errno = self.to_number();
            let slice = CStr::from_ptr(munge_strerror(errno));
            slice.to_str().unwrap().to_string()
        }
    }

    pub fn to_number(&self) -> u32 {
        match *self {
            MungeError::Snafu => 1,
            MungeError::BadArg => 2,
            MungeError::BadLength => 3,
            MungeError::Overflow => 4,
            MungeError::NoMemory => 5,
            MungeError::Socket => 6,
            MungeError::Timeout => 7,
            MungeError::BadCred => 8,
            MungeError::BadVersion => 9,
            MungeError::BadCipher => 10,
            MungeError::BadMac => 11,
            MungeError::BadZip => 12,
            MungeError::BadRealm => 13,
            MungeError::CredInvalid => 14,
            MungeError::CredExpired => 15,
            MungeError::CredRewound => 16,
            MungeError::CredReplayed => 17,
            MungeError::CredUnauthorized => 18,
        }
    }

    pub fn from_number(number: u32) -> MungeError {
        match number {
            1 => MungeError::Snafu,
            2 => MungeError::BadArg,
            3 => MungeError::BadLength,
            4 => MungeError::Overflow,
            5 => MungeError::NoMemory,
            6 => MungeError::Socket,
            7 => MungeError::Timeout,
            8 => MungeError::BadCred,
            9 => MungeError::BadVersion,
            10 => MungeError::BadCipher,
            11 => MungeError::BadMac,
            12 => MungeError::BadZip,
            13 => MungeError::BadRealm,
            14 => MungeError::CredInvalid,
            15 => MungeError::CredExpired,
            16 => MungeError::CredRewound,
            17 => MungeError::CredReplayed,
            18 => MungeError::CredUnauthorized,
            _ => panic!("Unknown error number"),
        }
    }
}

impl fmt::Display for MungeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

pub fn encode(payload: Option<&str>) -> Result<String, MungeError> {
    let mut cred: *mut i8 = std::ptr::null_mut();

    let result = if let Some(payload) = payload {
        let payload_cstring = CString::new(payload).unwrap();
        let payload_ptr = payload_cstring.as_ptr() as *const libc::c_void;

        unsafe {
            munge_encode(
                &mut cred,
                std::ptr::null_mut(),
                payload_ptr,
                payload.len() as i32,
            )
        }
    } else {
        unsafe { munge_encode(&mut cred, std::ptr::null_mut(), std::ptr::null_mut(), 0) }
    };

    if result != MUNGE_SUCCESS {
        return Err(MungeError::from_number(result));
    }

    assert!(!cred.is_null());
    let slice = unsafe { CStr::from_ptr(cred) };
    let cred = slice.to_str().unwrap().to_string();
    Ok(cred)
}

pub fn decode(cred: &str) -> Result<DecodedMessage, MungeError> {
    let mut payload: *mut libc::c_void = std::ptr::null_mut();
    let mut payload_length: i32 = 0;
    let mut uid: u32 = 0;
    let mut gid: u32 = 0;

    let result = unsafe {
        munge_decode(
            cred.as_ptr() as *const i8,
            std::ptr::null_mut(),
            &mut payload,
            &mut payload_length,
            &mut uid,
            &mut gid,
        )
    };
    if result != MUNGE_SUCCESS {
        return Err(MungeError::from_number(result));
    }

    let payload = if payload.is_null() {
        None
    } else {
        // Munge always gives us a null-terminated
        let slice = unsafe { CStr::from_ptr(payload as *const i8) };
        Some(slice.to_str().unwrap().to_string())
    };

    Ok(DecodedMessage { uid, gid, payload })
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, MungeError};

    #[test]
    fn test_that_mungeerror_works() {
        assert_eq!(MungeError::Snafu.to_string(), "Internal error");
        assert_eq!(MungeError::BadArg.to_string(), "Invalid argument");
    }

    #[test]
    fn test_that_encode_decode_round_trip_without_payload_works() {
        let message = decode(&encode(None).unwrap()).unwrap();
        assert_eq!(message.payload, None);
        assert!(message.uid > 0);
        assert!(message.gid > 0);
    }

    #[test]
    fn test_that_encode_decode_round_trip_with_payload_works() {
        let orig_payload = "abc";
        let message = decode(&encode(Some(orig_payload)).unwrap()).unwrap();
        let payload = message.payload();
        assert_eq!(payload, &Some(String::from(orig_payload)));
        assert!(message.uid() > 0);
        assert!(message.gid() > 0);
    }
}
