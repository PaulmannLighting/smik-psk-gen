use std::ops::Deref;
use std::str::FromStr;

use base64::Engine;

use crate::constants::BASE64;

/// A plain text key that can be decoded from base64.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct Base64Key(Box<[u8]>);

impl Deref for Base64Key {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromStr for Base64Key {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BASE64.decode(s).map(Vec::into_boxed_slice).map(Self)
    }
}
