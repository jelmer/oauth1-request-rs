//! Signature methods ([RFC 5849 section 3.4.][rfc]).
//!
//! [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4
//!
//! The OAuth standard allows for servers to implement their own custom signature methods.
//! So the module provides an abstraction over signature methods so that users can implement those
//! custom methods by themselves.

cfg_if! {
    if #[cfg(feature = "either")] {
        mod either;
    }
}

cfg_if! {
    if #[cfg(feature = "hmac-sha1")] {
        pub mod hmac_sha1;
        pub use self::hmac_sha1::HmacSha1;
    }
}

pub mod plaintext;

pub use self::plaintext::Plaintext;

use std::fmt::{Display, Write};

/// Types that represent a signature method.
///
/// This is used to construct a `Self::Sign` and carries configuration data for them.
pub trait SignatureMethod: Sized {
    /// The algorithm used by this signature method to sign a signature base string.
    type Sign: Sign<SignatureMethod = Self>;

    /// Returns the `oauth_signature_method` string for the signature method.
    fn name(&self) -> &'static str;

    /// If this method returns `false`, `Signer` will not emit the `oauth_nonce` part of the
    /// signature base string.
    ///
    /// The default implementation returns `true`.
    fn use_nonce(&self) -> bool {
        true
    }

    /// If this method returns `false`, `Signer` will not emit the `oauth_timestamp` part of the
    /// signature base string.
    ///
    /// The default implementation returns `true`.
    fn use_timestamp(&self) -> bool {
        true
    }
}

macro_rules! provide {
    ($(#[doc = $doc:expr])+ $name:ident, $($rest:tt)*) => {
        $(#[doc = $doc])+
        fn $name(&mut self, default_key: &'static str, value: impl Display) {
            self.parameter(default_key, value);
        }
        provide! { $($rest)* }
    };
    ($name:ident, $($rest:tt)*) => {
        provide! {
            #[doc = concat!(
"Feeds `self` with the `oauth_", stringify!($name), "` parameter part of the signature base string.

`default_key` argument is passed just for the convenience of implementors and is always `\"oauth_",
stringify!($name), "\"`.

The default implementation forwards to the `parameter` method."
            )]
            $name, $($rest)*
        }
    };
    () => {};
}

/// Algorithms to sign a signature base string ([RFC 5849 section 3.4.1.][rfc]).
///
/// [rfc]: https://tools.ietf.org/html/rfc5849#section-3.4.1
///
/// The type will be incrementally passed a signature base string. For example,
/// a signature base string like the following (line breaks are for display purposes only):
///
/// ```text
/// POST&
/// http%3A%2F%2Fexample.com%2Frequest&
/// a%3Dr%2520b
/// %26
/// a2%3Da
/// %26
/// oauth_consumer_key%3D9djdj82h48djs9d2
/// %26
/// oauth_nonce%3D7d8f3e4a
/// %26
/// oauth_signature_method%3DHMAC-SHA1
/// %26
/// oauth_timestamp%3D137131201
/// %26
/// oauth_token%3Dkkk9d7dh3k39sjv7
/// %26
/// z%3D
/// ```
///
/// ...is represented by a series of method calls like the following (`sign` is the `Sign` object):
///
/// ```
/// # use oauth1_request::signature_method::plaintext::{Plaintext, PlaintextSign};
/// # use oauth1_request::signature_method::Sign;
/// # let mut sign = PlaintextSign::new("", Some(""), Plaintext);
/// sign.request_method("POST");
/// sign.uri("http%3A%2F%2Fexample.com%2Frequest");
/// sign.parameter("a", "r%2520b");
/// sign.delimit();
/// sign.parameter("a2", "a");
/// sign.delimit();
/// sign.consumer_key("oauth_consumer_key", "9djdj82h48djs9d2");
/// sign.delimit();
/// sign.nonce("oauth_nonce", "7d8f3e4a");
/// sign.delimit();
/// sign.signature_method("oauth_signature_method", "HMAC-SHA1");
/// sign.delimit();
/// sign.timestamp("oauth_timestamp", 137131201);
/// sign.delimit();
/// sign.token("oauth_token", "kkk9d7dh3k39sjv7");
/// sign.delimit();
/// sign.parameter("z", "");
/// ```
pub trait Sign: Sized {
    /// The signature method associated with this algorithm.
    type SignatureMethod: SignatureMethod<Sign = Self>;
    type SignatureMethodRef<'a>: SignatureMethod<Sign = Self>;
    /// The representation of `oauth_signature` string the algorithm produces.
    type Signature: Display;

    /// Creates `Self` that signs a signature base string by the given client credentials.
    fn new(
        consumer_secret: impl Display,
        token_secret: Option<impl Display>,
        signature_method: Self::SignatureMethod,
    ) -> Self;

    /// Returns a reference to the underlying `SignatureMethod` object.
    fn get_signature_method(&self) -> Self::SignatureMethodRef;

    /// Feeds `self` with the HTTP request method part of the signature base string.
    fn request_method(&mut self, method: &str);

    /// Feeds `self` with the base string URI part of the signature base string.
    fn uri(&mut self, uri: impl Display);

    /// Feeds `self` with a key-value parameter pair of the signature base string.
    fn parameter(&mut self, key: &str, value: impl Display);

    /// Feeds `self` with the delimiter (`%26`) between parameters.
    fn delimit(&mut self);

    /// Finalizes the signing process and returns the resulting signature.
    fn finish(self) -> Self::Signature;

    provide! { callback, consumer_key, nonce, }

    /// Feeds `self` with the `oauth_signature_method` parameter part of the
    /// signature base string.
    ///
    /// `default_key` and `default_value` arguments are passed just for the convenience of
    /// implementors and are always `"oauth_signature_method"` and
    /// `self.get_signature_method().name()` respectively.
    ///
    /// The default implementation forwards to the `parameter` method."
    fn signature_method(&mut self, default_key: &'static str, default_value: &'static str) {
        self.parameter(default_key, default_value);
    }

    /// Feeds `self` with the `oauth_", stringify!($name), "` parameter part of the
    /// signature base string.
    ///
    /// `default_key` argument is passed just for the convenience of implementors and is always
    /// `"oauth_timestamp"`.
    ///
    /// The default implementation forwards to the `parameter` method.
    fn timestamp(&mut self, default_key: &'static str, value: u64) {
        self.parameter(default_key, value);
    }

    provide! { token, verifier, }

    /// Feeds `self` with the `oauth_version` parameter part of the signature base string.
    ///
    /// `default_key` and `default_value` arguments are passed just for the convenience of
    /// implementors and are always `"oauth_version"` and `"1.0"` respectively.
    ///
    /// The default implementation forwards to the `parameter` method.
    fn version(&mut self, default_key: &'static str, default_value: &'static str) {
        self.parameter(default_key, default_value);
    }
}

impl<'a, SM: SignatureMethod> SignatureMethod for &'a SM {
    type Sign = SM::Sign;

    fn name(&self) -> &'static str {
        SM::name(*self)
    }

    fn use_nonce(&self) -> bool {
        SM::use_nonce(*self)
    }

    fn use_timestamp(&self) -> bool {
        SM::use_timestamp(*self)
    }
}

fn signing_key(cs: impl Display, ts: Option<impl Display>) -> String {
    let mut ret = String::with_capacity(128);
    write!(ret, "{}&", cs).unwrap();
    if let Some(ts) = ts {
        write!(ret, "{}", ts).unwrap();
    }
    ret
}
