//! The `HMAC-SHA1` signature method ([RFC 5849 section 3.4.2.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.2
//!
//! This module is only available when `hmac-sha1` feature is activated.

extern crate base64;
extern crate hmac;
extern crate sha1;

use std::fmt::{self, Formatter};

use self::base64::display::Base64Display;
use self::hmac::{Hmac, Mac};
use self::sha1::digest::generic_array::GenericArray;
use self::sha1::digest::FixedOutput;
use self::sha1::Sha1;

use super::*;
use util::PercentEncode;

/// The `HMAC-SHA1` signature method.
#[derive(Copy, Clone, Debug, Default)]
pub struct HmacSha1;

/// A type that signs a signature base string with the HMAC-SHA1 signature algorithm.
pub struct HmacSha1Sign {
    mac: Hmac<Sha1>,
}

/// A signature produced by an `HmacSha1Sign`.
pub struct HmacSha1Signature {
    signature: GenericArray<u8, <Sha1 as FixedOutput>::OutputSize>,
}

/// Wrapper to implement `fmt::Write` for `M: Mac`.
struct MacWrite<'a, M: 'a>(&'a mut M);

impl SignatureMethod for HmacSha1 {
    type Sign = HmacSha1Sign;
}

impl Sign for HmacSha1Sign {
    type SignatureMethod = HmacSha1;
    type Signature = HmacSha1Signature;

    fn new(
        consumer_secret: impl Display,
        token_secret: Option<impl Display>,
        _signature_method: HmacSha1,
    ) -> Self {
        let signing_key = signing_key(consumer_secret, token_secret);
        HmacSha1Sign {
            mac: Hmac::new_varkey(signing_key.as_bytes()).unwrap(),
        }
    }

    fn get_signature_method_name(&self) -> &'static str {
        "HMAC-SHA1"
    }

    fn request_method(&mut self, method: &str) {
        self.mac.input(method.as_bytes());
        self.mac.input(b"&");
    }

    fn uri(&mut self, uri: impl Display) {
        write!(MacWrite(&mut self.mac), "{}&", uri).unwrap();
    }

    fn parameter(&mut self, key: &str, value: impl Display) {
        self.mac.input(key.as_bytes());
        self.mac.input(b"%3D"); // '='
        write!(MacWrite(&mut self.mac), "{}", value).unwrap();
    }

    fn delimit(&mut self) {
        self.mac.input(b"%26"); // '&'
    }

    fn finish(self) -> HmacSha1Signature {
        HmacSha1Signature {
            signature: self.mac.result().code(),
        }
    }
}

impl Display for HmacSha1Signature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&PercentEncode(Base64Display::standard(&self.signature)), f)
    }
}

impl<'a, M: Mac> Write for MacWrite<'a, M> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0.input(s.as_bytes());
        Ok(())
    }
}
