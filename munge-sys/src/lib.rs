#![allow(bad_style)]

/* automatically generated by rust-bindgen */
use ::libc::{c_char, c_int, c_void, gid_t, uid_t};

#[repr(C)]
pub struct munge_ctx {
    _private: [u8; 0],
}
pub type munge_ctx_t = *mut munge_ctx;

/// Data Types
pub mod MungeOpt {
    pub type Type = u32;

    pub const CIPHER_TYPE: Type = 0;
    pub const MAC_TYPE: Type = 1;
    pub const ZIP_TYPE: Type = 2;
    pub const REALM: Type = 3;
    pub const TTL: Type = 4;
    pub const ADDR4: Type = 5;
    pub const ENCODE_TIME: Type = 6;
    pub const DECODE_TIME: Type = 7;
    pub const SOCKET: Type = 8;
    pub const UID_RESTRICTION: Type = 9;
    pub const GID_RESTRICTION: Type = 10;
}
pub use self::MungeOpt::Type as munge_opt_t;

pub mod MungeEnum {
    pub type Type = u32;

    pub const CIPHER: Type = 0;
    pub const MAC: Type = 1;
    pub const ZIP: Type = 2;
}
pub use self::MungeEnum::Type as munge_enum_t;

pub mod MungeErr {
    pub type Type = u32;

    pub const SUCCESS: Type = 0;
    pub const SNAFU: Type = 1;
    pub const BAD_ARG: Type = 2;
    pub const BAD_LENGTH: Type = 3;
    pub const OVERFLOW: Type = 4;
    pub const NO_MEMORY: Type = 5;
    pub const SOCKET: Type = 6;
    pub const TIMEOUT: Type = 7;
    pub const BAD_CRED: Type = 8;
    pub const BAD_VERSION: Type = 9;
    pub const BAD_CIPHER: Type = 10;
    pub const BAD_MAC: Type = 11;
    pub const BAD_ZIP: Type = 12;
    pub const BAD_REALM: Type = 13;
    pub const CRED_INVALID: Type = 14;
    pub const CRED_EXPIRED: Type = 15;
    pub const CRED_REWOUND: Type = 16;
    pub const CRED_REPLAYED: Type = 17;
    pub const CRED_UNAUTHORIZED: Type = 18;
}
pub use self::MungeErr::Type as munge_err_t;

/// Free stuff allocated by munge.
#[inline]
pub unsafe extern "C" fn munge_free (ptr: *mut c_void) {
    ::libc::free(ptr);
}

/// Primary Functions
pub mod main { use super::*; extern "C" {
    pub fn munge_encode(
        cred: *mut *const c_char,
        ctx: munge_ctx_t,
        buf: *const c_void,
        len: c_int,
    ) -> munge_err_t;

    pub fn munge_decode(
        cred: *const c_char,
        ctx: munge_ctx_t,
        buf: *mut *mut c_void,
        len: *mut c_int,
        uid: *mut uid_t,
        gid: *mut gid_t,
    ) -> munge_err_t;

    pub fn munge_strerror(ctx: munge_err_t) -> *const c_char;
}}
pub use self::main::*;

/// Context Functions
///
/// The context passed to munge_encode() is treated read-only except for the
/// error message that is set when an error is returned. The context passed to
/// munge_decode() is set according to the context used to encode the
/// credential; however, on error, its settings may be in a state which is
/// invalid for encoding.
///
/// Consequently, separate contexts should be used for encoding and decoding.
///
/// A context should not be shared between threads unless it is protected by a
/// mutex; however, a better alternative is to use a separate context (or two)
/// for each thread, either by creating a new one or copying an existing one.
pub mod context { use super::*; extern "C" {
    pub fn munge_ctx_create() -> munge_ctx_t;

    pub fn munge_ctx_copy(ctx: munge_ctx_t) -> munge_ctx_t;

    pub fn munge_ctx_destroy(ctx: munge_ctx_t);

    pub fn munge_ctx_strerror(ctx: munge_ctx_t) -> *const c_char;

    pub fn munge_ctx_get(
        ctx: munge_ctx_t,
        opt: munge_opt_t,
        ...
    ) -> munge_err_t;

    pub fn munge_ctx_set(
        ctx: munge_ctx_t,
        opt: munge_opt_t,
        ...
    ) -> munge_err_t;
}}
pub use self::context::*;

/// Enumeration Functions
pub mod munge_enum { use super::*; extern "C" {
    pub fn munge_enum_is_valid(ty: munge_enum_t, val: c_int) -> c_int;

    pub fn munge_enum_int_to_str(ty: munge_enum_t, val: c_int) -> *const c_char;

    pub fn munge_enum_str_to_int(ty: munge_enum_t, str: *const c_char) -> c_int;
}}
pub use self::munge_enum::*;
