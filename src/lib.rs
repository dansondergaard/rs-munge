extern crate libc;
extern crate munge_sys;

use std::error;
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

impl error::Error for MungeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
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
        unsafe { libc::free(cred as *mut libc::c_void) };
        return Err(MungeError::from_number(result));
    }

    assert!(!cred.is_null());
    let slice = unsafe { CStr::from_ptr(cred) };
    let owned_cred = slice.to_str().unwrap().to_string();
    unsafe {
        libc::free(cred as *mut libc::c_void);
    };
    Ok(owned_cred)
}

pub fn decode(cred: &str) -> Result<DecodedMessage, MungeError> {
    let mut payload: *mut libc::c_void = std::ptr::null_mut();
    let mut payload_length: i32 = 0;
    let mut uid: u32 = 0;
    let mut gid: u32 = 0;

    let result = unsafe {
        munge_decode(
            cred.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            &mut payload,
            &mut payload_length,
            &mut uid,
            &mut gid,
        )
    };
    if result != MUNGE_SUCCESS {
        if !payload.is_null() {
            unsafe { libc::free(payload) };
        }
        return Err(MungeError::from_number(result));
    }

    let payload = if payload.is_null() && payload_length == 0 {
        None
    } else {
        let owned_payload = unsafe {
            String::from_raw_parts(
                payload as *mut _,
                payload_length as usize,
                payload_length as usize,
            )
        };
        Some(owned_payload)
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

    #[test]
    fn test_do_we_have_a_memory_leak() {
        let orig_payload = "abcdefg";
        let memory_before = procinfo::pid::statm_self().unwrap().resident;
        for _ in 1..1000 {
            let _message = decode(&encode(Some(orig_payload)).unwrap()).unwrap();
        }
        let memory_after = procinfo::pid::statm_self().unwrap().resident;
        assert_eq!(memory_before, memory_after);
    }
}
