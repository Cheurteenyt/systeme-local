use core::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

const DIGEST_BYTES: usize = 32;
const DIGEST_HEX_LENGTH: usize = DIGEST_BYTES * 2;

/// A canonical lowercase SHA-256 or HMAC-SHA-256 value.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Digest([u8; DIGEST_BYTES]);

impl Digest {
    /// The all-zero genesis digest.
    pub const ZERO: Self = Self([0; DIGEST_BYTES]);

    /// Builds a digest from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; DIGEST_BYTES]) -> Self {
        Self(bytes)
    }

    /// Parses exactly 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`DigestParseError`] when the input length or encoding is not
    /// canonical lowercase hexadecimal.
    pub fn parse(value: &str) -> Result<Self, DigestParseError> {
        if value.len() != DIGEST_HEX_LENGTH {
            return Err(DigestParseError::Length {
                actual: value.len(),
            });
        }

        let encoded = value.as_bytes();
        let mut decoded = [0_u8; DIGEST_BYTES];
        for (output_index, pair) in encoded.chunks_exact(2).enumerate() {
            let high_index = output_index * 2;
            let high = decode_nibble(pair[0], high_index)?;
            let low = decode_nibble(pair[1], high_index + 1)?;
            decoded[output_index] = (high << 4) | low;
        }
        Ok(Self(decoded))
    }
}

fn decode_nibble(byte: u8, index: usize) -> Result<u8, DigestParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Err(DigestParseError::Uppercase { index }),
        _ => Err(DigestParseError::Character { index }),
    }
}

/// Why a digest string is not canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestParseError {
    /// The encoded digest is not exactly 64 bytes.
    Length {
        /// Actual encoded length.
        actual: usize,
    },
    /// A non-hexadecimal character was found.
    Character {
        /// Byte position of the character.
        index: usize,
    },
    /// Uppercase hexadecimal is rejected to keep one canonical encoding.
    Uppercase {
        /// Byte position of the uppercase character.
        index: usize,
    },
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { actual } => {
                write!(
                    formatter,
                    "digest must contain exactly {DIGEST_HEX_LENGTH} lowercase hexadecimal \
                     characters; got {actual}"
                )
            }
            Self::Character { index } => {
                write!(
                    formatter,
                    "digest contains a non-hexadecimal byte at index {index}"
                )
            }
            Self::Uppercase { index } => {
                write!(
                    formatter,
                    "digest contains uppercase hexadecimal at index {index}"
                )
            }
        }
    }
}

impl std::error::Error for DigestParseError {}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

struct DigestVisitor;

impl Visitor<'_> for DigestVisitor {
    type Value = Digest;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("exactly 64 lowercase hexadecimal characters")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Digest::parse(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(DigestVisitor)
    }
}
