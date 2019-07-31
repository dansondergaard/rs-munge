extern crate libc;
extern crate munge_sys;

use std::ffi::{CStr, CString};
use std::fmt;

use munge_sys::{munge_decode, munge_encode, munge_strerror, MUNGE_SUCCESS};

#[derive(Debug)]
struct DecodedMessage {
    pub uid: u32,
    pub gid: u32,
    pub payload: String,
}

#[derive(Debug)]
enum MungeError {
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

    fn to_number(&self) -> u32 {
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

    fn from_number(number: u32) -> MungeError {
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

fn encode(message: &str) -> Result<String, MungeError> {
    let mut cred: *mut i8 = std::ptr::null_mut();

    let payload = CString::new(message).unwrap();
    let payload_ptr = payload.as_ptr() as *const libc::c_void;

    let result = unsafe {
        munge_encode(
            &mut cred,
            std::ptr::null_mut(),
            payload_ptr,
            message.len() as i32,
        )
    };

    if result != MUNGE_SUCCESS {
        return Err(MungeError::from_number(result));
    }

    assert!(!cred.is_null());
    let slice = unsafe { CStr::from_ptr(cred) };
    let message = slice.to_str().unwrap().to_string();
    Ok(message)
}

fn decode(message: &str) -> Result<DecodedMessage, MungeError> {
    let mut payload: *mut libc::c_void = std::ptr::null_mut();
    let mut payload_length: i32 = 0;
    let mut uid: u32 = 0;
    let mut gid: u32 = 0;

    let result = unsafe {
        munge_decode(
            message.as_ptr() as *const i8,
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

    let slice = unsafe { CStr::from_ptr(payload as *const i8) };
    let payload = slice.to_str().unwrap().to_string();

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
    fn test_that_encode_decode_round_trip_works() {
        let payload = "abc";
        let decoded = decode(&encode(payload).unwrap()).unwrap();
        assert_eq!(decoded.payload, payload);
        assert!(decoded.uid > 0);
        assert!(decoded.gid > 0);
    }
}
