use alloc::string::String;
use core::fmt;

/// A validated session identifier.
///
/// Session IDs have the form `ox_<8 alphanumeric chars>`, e.g. `ox_k7m3qx9p`.
/// This newtype ensures session IDs are always well-formed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    /// The prefix for all session IDs.
    pub const PREFIX: &str = "ox_";

    /// The length of the random suffix.
    pub const SUFFIX_LEN: usize = 8;

    /// Create a new `SessionId` from a raw string, validating the format.
    ///
    /// Returns `None` if the string doesn't match `ox_<8 alphanumeric chars>`.
    pub fn new(s: String) -> Option<Self> {
        if Self::is_valid(&s) {
            Some(Self(s))
        } else {
            None
        }
    }

    /// Check whether a string is a valid session ID.
    pub fn is_valid(s: &str) -> bool {
        s.len() == Self::PREFIX.len() + Self::SUFFIX_LEN
            && s.starts_with(Self::PREFIX)
            && s[Self::PREFIX.len()..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
    }
}

impl From<String> for SessionId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for SessionId {
    fn from(s: &str) -> Self {
        Self(String::from(s))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SessionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
