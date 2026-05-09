//! UID → username resolution with caching.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Cached UID → username map, loaded once from `/etc/passwd` at startup.
///
/// Falls back to displaying the raw UID number if the user is not found.
static PASSWD_CACHE: LazyLock<HashMap<u32, String>> = LazyLock::new(load_passwd);

/// Parse `/etc/passwd` into a UID → username map.
fn load_passwd() -> HashMap<u32, String> {
    let mut map = HashMap::new();
    let Ok(contents) = std::fs::read_to_string("/etc/passwd") else {
        return map;
    };
    for line in contents.lines() {
        // Format: username:x:uid:gid:gecos:home:shell
        let fields: Vec<&str> = line.splitn(4, ':').collect();
        if fields.len() >= 3
            && let Ok(uid) = fields[2].parse::<u32>()
        {
            map.insert(uid, fields[0].to_owned());
        }
    }
    map
}

/// Resolve a username to a UID. Returns `None` if not found.
pub fn resolve_username(name: &str) -> Option<u32> {
    PASSWD_CACHE
        .iter()
        .find(|(_, v)| v.as_str() == name)
        .map(|(k, _)| *k)
}

/// Resolve a UID to a username. Returns the UID as a string if not found.
pub fn resolve_uid(uid: u32) -> String {
    PASSWD_CACHE
        .get(&uid)
        .cloned()
        .unwrap_or_else(|| uid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_uid_root() {
        // Root (uid 0) should always exist on Linux.
        let name = resolve_uid(0);
        assert_eq!(name, "root");
    }

    #[test]
    fn resolve_uid_unknown() {
        // An absurdly high UID should fall back to numeric display.
        let name = resolve_uid(99999);
        assert_eq!(name, "99999");
    }

    #[test]
    fn load_passwd_returns_map() {
        let map = load_passwd();
        // Should have at least root.
        assert!(map.contains_key(&0), "should contain root");
    }
}
