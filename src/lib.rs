use ::libc::{
    c_char,
    c_int,
    c_void,
};
use ::munge_sys::{
    munge_decode,
    munge_encode,
    munge_free,
    munge_strerror,
    MungeErr,
};
use ::std::{*,
    borrow::{
        Cow,
        ToOwned,
    },
    convert::{
        TryInto,
    },
    ffi::{
        CStr,
        CString,
    },
    ops::Not,
};

#[derive(
    Debug,
    Default,
    Clone,
    PartialEq, Eq,
)]
pub struct DecodedMessage {
    uid: u32,
    gid: u32,
    payload: Option<Vec<u8>>,
}

impl DecodedMessage {
    #[inline]
    pub
    fn uid (self: &'_ Self) -> u32
    {
        self.uid
    }

    #[inline]
    pub
    fn gid (self: &'_ Self) -> u32
    {
        self.gid
    }

    #[inline]
    pub
    fn payload (self: &'_ Self) -> Option<&'_ [u8]>
    {
        self.payload.as_ref().map(Vec::as_slice)
    }
}

#[derive(
    Debug,
    Clone, Copy,
    PartialEq, Eq,
)]
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

impl fmt::Display for MungeError {
    fn fmt (self: &'_ Self, stream: &'_ mut fmt::Formatter<'_>) -> fmt::Result
    {
        self.with_str(|s| write!(stream, "{}", s))
    }
}

impl error::Error for MungeError {}

impl MungeError {
    pub
    fn with_str<R, F> (self: &'_ Self, f: F) -> R
    where
        F : FnOnce(Cow<str>) -> R,
    {
        let errno = self.to_number();
        let slice = unsafe {
            CStr::from_ptr(munge_strerror(errno))
        };
        f(slice.to_string_lossy())
    }

    #[inline]
    pub
    fn to_string (self: &'_ Self) -> String
    {
        self.with_str(|s| s.into_owned())
    }

    pub
    fn to_number (self: &'_ Self) -> MungeErr::Type
    {
        match *self {
            | MungeError::Snafu => MungeErr::SNAFU,
            | MungeError::BadArg => MungeErr::BAD_ARG,
            | MungeError::BadLength => MungeErr::BAD_LENGTH,
            | MungeError::Overflow => MungeErr::OVERFLOW,
            | MungeError::NoMemory => MungeErr::NO_MEMORY,
            | MungeError::Socket => MungeErr::SOCKET,
            | MungeError::Timeout => MungeErr::TIMEOUT,
            | MungeError::BadCred => MungeErr::BAD_CRED,
            | MungeError::BadVersion => MungeErr::BAD_VERSION,
            | MungeError::BadCipher => MungeErr::BAD_CIPHER,
            | MungeError::BadMac => MungeErr::BAD_MAC,
            | MungeError::BadZip => MungeErr::BAD_ZIP,
            | MungeError::BadRealm => MungeErr::BAD_REALM,
            | MungeError::CredInvalid => MungeErr::CRED_INVALID,
            | MungeError::CredExpired => MungeErr::CRED_EXPIRED,
            | MungeError::CredRewound => MungeErr::CRED_REWOUND,
            | MungeError::CredReplayed => MungeErr::CRED_REPLAYED,
            | MungeError::CredUnauthorized => MungeErr::CRED_UNAUTHORIZED,
        }
    }

    pub
    fn try_from_number (number: MungeErr::Type) -> Option<Self>
    {
        Some(match number {
            | MungeErr::SNAFU => MungeError::Snafu,
            | MungeErr::BAD_ARG => MungeError::BadArg,
            | MungeErr::BAD_LENGTH => MungeError::BadLength,
            | MungeErr::OVERFLOW => MungeError::Overflow,
            | MungeErr::NO_MEMORY => MungeError::NoMemory,
            | MungeErr::SOCKET => MungeError::Socket,
            | MungeErr::TIMEOUT => MungeError::Timeout,
            | MungeErr::BAD_CRED => MungeError::BadCred,
            | MungeErr::BAD_VERSION => MungeError::BadVersion,
            | MungeErr::BAD_CIPHER => MungeError::BadCipher,
            | MungeErr::BAD_MAC => MungeError::BadMac,
            | MungeErr::BAD_ZIP => MungeError::BadZip,
            | MungeErr::BAD_REALM => MungeError::BadRealm,
            | MungeErr::CRED_INVALID => MungeError::CredInvalid,
            | MungeErr::CRED_EXPIRED => MungeError::CredExpired,
            | MungeErr::CRED_REWOUND => MungeError::CredRewound,
            | MungeErr::CRED_REPLAYED => MungeError::CredReplayed,
            | MungeErr::CRED_UNAUTHORIZED => MungeError::CredUnauthorized,
            | _ => return None,
        })
    }
}

#[derive(
    Debug,
    Clone, Copy,
    PartialEq, Eq,
)]
pub enum Error {
    MungeError(MungeError),
    InvalidUtf8,
    InnerNull,
}

impl From<MungeError> for Error {
    #[inline]
    fn from (munge_error: MungeError) -> Error
    {
        Error::MungeError(munge_error)
    }
}

impl fmt::Display for Error {
    fn fmt (
        self: &'_ Self,
        stream : &'_ mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Error::MungeError(ref munge_err) => write!(stream,
                "munge errored: {}", munge_err,
            ),
            | Error::InvalidUtf8 => write!(stream,
                "C string to Rust string lift failed: got non UTF8 output",
            ),
            | Error::InnerNull => write!(stream,
                "Rust string to C string lift failed: input had inner null",
            ),
        }
    }
}

impl error::Error for Error {
    fn source (
        self: &'_ Self,
    ) -> Option<&'_ (dyn error::Error + 'static)>
    {
        if let &Error::MungeError(ref munge_error) = self {
            Some(munge_error as _)
        } else {
            None
        }
    }
}

pub
fn encode (
    payload: Option<&'_ [u8]>,
) -> Result<String, Error>
{
    let mut cred: *const c_char = std::ptr::null();
    let (payload_ptr, payload_len) = if let Some(payload) = payload {
        (
            payload
                .as_ptr()
                as *const c_void
            ,
            payload
                .len()
                .try_into()
                .expect("payload length overflow")
            ,
        )
    } else {
        (
            ptr::null(),
            0,
        )
    };

    let result = unsafe {
        munge_encode(
            &mut cred,
            std::ptr::null_mut(),
            payload_ptr,
            payload_len,
        )
    };

    ::scopeguard::defer!(unsafe {
        munge_free(cred as *mut c_void);
    });

    if result != MungeErr::SUCCESS {
        return Err(
            MungeError::try_from_number(result)
                .unwrap()
                .into()
        );
    } else {
        assert!(cred.is_null().not());
    }
    let owned_cred = String::from_utf8(
        // convert to an owned `String`, but including the final nul byte
        unsafe { CStr::from_ptr(cred) }
            .to_bytes_with_nul()
            .to_owned()
    ).map_err(|_| Error::InvalidUtf8)?;
    Ok(owned_cred)
}

pub
fn decode (
    cred: impl Into<String> + AsRef<str>
) -> Result<DecodedMessage, Error>
{
    let mut ret = DecodedMessage::default();
    let mut payload_ptr: *mut c_void = std::ptr::null_mut();
    let mut payload_length: c_int = 0;

    let buffer: CString;
    let cred: &CStr = match cred.as_ref().bytes().position(|x| x == b'\0') {
        | None => {
            let mut bytes = <Vec<u8> as From<String>>::from(cred.into());
            bytes.reserve_exact(1);
            bytes.push(b'\0');
            buffer = unsafe {
                CString::from_vec_unchecked(bytes)
            };
            &*buffer
        },
        | Some(len) if len + 1 >= cred.as_ref().len() => unsafe {
            CStr::from_bytes_with_nul_unchecked(cred.as_ref().as_bytes())
        },
        | _ => {
            return Err(Error::InnerNull);
        },
    };
    let result = unsafe {
        munge_decode(
            cred.as_ptr() as *const c_char,
            std::ptr::null_mut(),
            &mut payload,
            &mut payload_length,
            &mut ret.uid,
            &mut ret.gid,
        )
    };
    ::scopeguard::defer!(unsafe {
        munge_free(payload_ptr);
    });
    if result != MungeErr::SUCCESS {
        return Err(
            MungeError::try_from_number(result)
                .unwrap()
                .into()
        );
    }
    if payload_ptr.is_null().not() {
        ret.payload = Some(unsafe {
            slice::from_raw_parts(
                payload_ptr as *const u8,
                payload_length.try_into().expect("Got payload_length < 0"),
            )
        }.to_owned());
    }
    Ok(ret)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, MungeError};

    static MEM_TEST: ::spin::RwLock<()> = ::spin::RwLock::new(());

    #[test]
    fn test_that_mungeerror_works() {
        match MEM_TEST.read() { _ => {
            assert_eq!(MungeError::Snafu.to_string(), "Internal error");
            assert_eq!(MungeError::BadArg.to_string(), "Invalid argument");
        }}
    }

    #[test]
    fn test_that_encode_decode_round_trip_without_payload_works() {
        match MEM_TEST.read() { _ => {
            let message = decode(&encode(None).unwrap()).unwrap();
            assert_eq!(message.payload, None);
            assert!(message.uid > 0);
            assert!(message.gid > 0);
        }}
    }

    #[test]
    fn test_that_encode_decode_round_trip_with_payload_works() {
        match MEM_TEST.read() { _ => {
            let orig_payload = &b"abc"[..];
            let message =
                decode(
                    &encode(Some(orig_payload)).unwrap()
                ).unwrap();
            let payload = message.payload();
            assert_eq!(payload, Some(orig_payload));
            assert!(message.uid() > 0);
            assert!(message.gid() > 0);
        }}
    }

    #[test]
    fn test_do_we_have_a_memory_leak() {
        match MEM_TEST.write() { _ => {
            let orig_payload = &b"abcdefg"[..];
            let memory_before = procinfo::pid::statm_self().unwrap().resident;
            for _ in 1 .. 1_000 {
                let _ = decode(&encode(Some(orig_payload)).unwrap()).unwrap();
            }
            let memory_after = procinfo::pid::statm_self().unwrap().resident;
            assert_eq!(memory_before, memory_after);
        }}
    }
}
