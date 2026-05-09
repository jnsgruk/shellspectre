use core::fmt;

/// Discriminant for the type of event captured.
///
/// Note: variant 1 was removed (formerly `IO_ENTER`). The gap is intentional
/// to preserve backwards compatibility with persisted event data.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(serde::Serialize, serde::Deserialize))]
pub enum EventType {
    Exec = 0,
    // Variant 1 (formerly IO_ENTER) is reserved — do not reuse.
    /// A read syscall I/O event.
    Read = 2,
    Write = 3,
    Exit = 4,
}

impl EventType {
    /// Decode an event type from the raw wire discriminant.
    pub const fn from_wire(value: u32) -> Option<Self> {
        match value {
            0 => Some(Self::Exec),
            2 => Some(Self::Read),
            3 => Some(Self::Write),
            4 => Some(Self::Exit),
            _ => None,
        }
    }

    /// Encode the event type to the raw wire discriminant.
    pub const fn as_wire(self) -> u32 {
        self as u32
    }

    /// Human-readable lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Read => "read",
            Self::Write => "write",
            Self::Exit => "exit",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown event type string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEventTypeError(());

impl fmt::Display for ParseEventTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown event type")
    }
}

impl core::str::FromStr for EventType {
    type Err = ParseEventTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "exec" => Ok(Self::Exec),
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "exit" => Ok(Self::Exit),
            _ => Err(ParseEventTypeError(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_discriminants() {
        assert_eq!(EventType::Exec as u32, 0);
        assert_eq!(EventType::Read as u32, 2);
        assert_eq!(EventType::Write as u32, 3);
        assert_eq!(EventType::Exit as u32, 4);
    }

    #[test]
    fn event_type_from_wire_rejects_unknown_values() {
        assert_eq!(EventType::from_wire(1), None);
        assert_eq!(EventType::from_wire(99), None);
    }

    #[test]
    fn event_type_display() {
        extern crate alloc;
        use alloc::string::ToString;
        assert_eq!(EventType::Exec.to_string(), "exec");
        assert_eq!(EventType::Read.to_string(), "read");
        assert_eq!(EventType::Write.to_string(), "write");
        assert_eq!(EventType::Exit.to_string(), "exit");
    }

    #[test]
    fn event_type_as_str() {
        assert_eq!(EventType::Exec.as_str(), "exec");
        assert_eq!(EventType::Read.as_str(), "read");
        assert_eq!(EventType::Write.as_str(), "write");
        assert_eq!(EventType::Exit.as_str(), "exit");
    }

    #[test]
    fn event_type_from_str() {
        use core::str::FromStr;
        assert_eq!(EventType::from_str("exec"), Ok(EventType::Exec));
        assert_eq!(EventType::from_str("read"), Ok(EventType::Read));
        assert_eq!(EventType::from_str("write"), Ok(EventType::Write));
        assert_eq!(EventType::from_str("exit"), Ok(EventType::Exit));
        assert!(EventType::from_str("unknown").is_err());
        assert!(EventType::from_str("EXEC").is_err());
    }

    #[test]
    fn event_type_display_roundtrips() {
        extern crate alloc;
        use alloc::string::ToString;
        use core::str::FromStr;
        for et in [
            EventType::Exec,
            EventType::Read,
            EventType::Write,
            EventType::Exit,
        ] {
            let s = et.to_string();
            let parsed = EventType::from_str(&s).expect("should roundtrip");
            assert_eq!(parsed, et);
        }
    }
}
