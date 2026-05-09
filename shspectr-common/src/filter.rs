use core::fmt;

/// The expected value type for a filter keyword.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ValueType {
    /// Numeric value (e.g. PID, UID, exit code).
    Number,
    /// Free-form text value.
    Text,
    /// Glob pattern with `*` and `?` wildcards.
    Glob,
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number => f.write_str("number"),
            Self::Text => f.write_str("text"),
            Self::Glob => f.write_str("glob"),
        }
    }
}

/// Metadata for a filter keyword, used for autocompletion and help.
#[derive(Debug, Clone, Copy)]
pub struct FilterKeywordMeta {
    /// The keyword name (e.g. "pid", "ppid").
    pub keyword: &'static str,
    /// Human-readable description.
    pub description: &'static str,
    /// Expected value type.
    pub value_type: ValueType,
    /// Example usage.
    pub example: &'static str,
    /// Whether this keyword supports `!` negation.
    pub supports_negation: bool,
}

/// All supported filter keywords.
pub const FILTER_KEYWORDS: &[FilterKeywordMeta] = &[
    FilterKeywordMeta {
        keyword: "pid",
        description: "Process ID",
        value_type: ValueType::Number,
        example: "pid:1234",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "ppid",
        description: "Parent process ID",
        value_type: ValueType::Number,
        example: "ppid:1",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "user",
        description: "Username or UID",
        value_type: ValueType::Text,
        example: "user:root",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "comm",
        description: "Kernel task name (supports * and ? globs)",
        value_type: ValueType::Glob,
        example: "comm:bash",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "cmd",
        description: "Command name from path (supports * and ? globs)",
        value_type: ValueType::Glob,
        example: "cmd:git",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "exit",
        description: "Exit code",
        value_type: ValueType::Number,
        example: "exit:0",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "session",
        description: "Session ID (prefix match)",
        value_type: ValueType::Text,
        example: "session:ox_abc",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "gid",
        description: "Group ID",
        value_type: ValueType::Number,
        example: "gid:1000",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "euid",
        description: "Effective user ID",
        value_type: ValueType::Number,
        example: "euid:0",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "tty",
        description: "TTY number (0 = no PTY)",
        value_type: ValueType::Number,
        example: "tty:34816",
        supports_negation: true,
    },
    FilterKeywordMeta {
        keyword: "file",
        description: "Executable path (supports * and ? globs)",
        value_type: ValueType::Glob,
        example: "file:/usr/bin/*",
        supports_negation: true,
    },
];
