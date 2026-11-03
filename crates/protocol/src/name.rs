//! Tunnel name rules: `^[a-z0-9-]{3,32}$` after lowercasing, no leading or
//! trailing `-`, and not in [`RESERVED_NAMES`].

/// Names that can never be registered.
pub const RESERVED_NAMES: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "www",
    "root",
    "system",
    "server",
    "relay",
    "kikonnect",
    "localhost",
    "status",
    "health",
    "support",
    "help",
    "mail",
    "ftp",
];

/// Minimum name length.
pub const MIN_NAME_LEN: usize = 3;
/// Maximum name length.
pub const MAX_NAME_LEN: usize = 32;

/// Why a name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    /// Shorter than [`MIN_NAME_LEN`].
    #[error("name must be at least {MIN_NAME_LEN} characters long")]
    TooShort,
    /// Longer than [`MAX_NAME_LEN`].
    #[error("name must be at most {MAX_NAME_LEN} characters long")]
    TooLong,
    /// Contains a character outside `a-z`, `0-9`, `-`.
    #[error("name may only contain letters a-z, digits and '-' (found {0:?})")]
    InvalidChar(char),
    /// Starts or ends with `-`.
    #[error("name must not start or end with '-'")]
    EdgeHyphen,
    /// In [`RESERVED_NAMES`].
    #[error("name '{0}' is reserved")]
    Reserved(String),
}

/// Trims surrounding whitespace, lowercases and validates a tunnel name.
///
/// Returns the normalized name.
pub fn normalize_name(input: &str) -> Result<String, NameError> {
    let name = input.trim().to_lowercase();
    if let Some(c) = name
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        return Err(NameError::InvalidChar(c));
    }
    // Only ASCII from here on, so byte length == char count.
    if name.len() < MIN_NAME_LEN {
        return Err(NameError::TooShort);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(NameError::EdgeHyphen);
    }
    if RESERVED_NAMES.contains(&name.as_str()) {
        return Err(NameError::Reserved(name));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_names() {
        assert_eq!(normalize_name("kilian").unwrap(), "kilian");
        assert_eq!(normalize_name("  KiLiAn  ").unwrap(), "kilian");
        assert_eq!(normalize_name("my-server-01").unwrap(), "my-server-01");
        assert_eq!(normalize_name("abc").unwrap(), "abc");
        assert_eq!(normalize_name(&"a".repeat(32)).unwrap(), "a".repeat(32));
        assert_eq!(normalize_name("a--b").unwrap(), "a--b");
    }

    #[test]
    fn invalid_names() {
        assert_eq!(normalize_name("ab"), Err(NameError::TooShort));
        assert_eq!(normalize_name(""), Err(NameError::TooShort));
        assert_eq!(normalize_name(&"a".repeat(33)), Err(NameError::TooLong));
        assert_eq!(normalize_name("-abc"), Err(NameError::EdgeHyphen));
        assert_eq!(normalize_name("abc-"), Err(NameError::EdgeHyphen));
        assert_eq!(normalize_name("ab c"), Err(NameError::InvalidChar(' ')));
        assert_eq!(normalize_name("ab_c"), Err(NameError::InvalidChar('_')));
        assert_eq!(normalize_name("äbc"), Err(NameError::InvalidChar('ä')));
        assert_eq!(normalize_name("ab.c"), Err(NameError::InvalidChar('.')));
        assert!(matches!(
            normalize_name("Admin"),
            Err(NameError::Reserved(_))
        ));
        assert!(matches!(normalize_name("www"), Err(NameError::Reserved(_))));
        assert!(matches!(normalize_name("api"), Err(NameError::Reserved(_))));
    }
}
