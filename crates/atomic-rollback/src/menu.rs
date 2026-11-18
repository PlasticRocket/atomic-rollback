//! GRUB's boot menu: the entries Fedora's blscfg adds from the BLS
//! directory and the order it adds them in (Fedora's grub2 2.12 patches,
//! grub-core/commands/blscfg.c).

/// rpm's version comparison as blscfg.c carries it (vercmp): 1 when a is
/// newer, -1 when b is, 0 when they compare the same. Separators other
/// than '~' and '+' are skipped; '~' sorts before everything, '+' after
/// the end; an alphabetic segment against a numeric one is older; numeric
/// segments compare by value, leading zeros dropped.
pub fn vercmp(a: &[u8], b: &[u8]) -> i32 {
    if a == b {
        return 0;
    }
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let skipped = |c: u8| c != 0 && !c.is_ascii_alphanumeric() && c != b'~' && c != b'+';
    let (mut one, mut two) = (0, 0);
    while at(a, one) != 0 || at(b, two) != 0 {
        while skipped(at(a, one)) {
            one += 1;
        }
        while skipped(at(b, two)) {
            two += 1;
        }
        let (x, y) = (at(a, one), at(b, two));
        if x == b'~' || y == b'~' {
            if x != b'~' {
                return 1;
            }
            if y != b'~' {
                return -1;
            }
            one += 1;
            two += 1;
            continue;
        }
        if x == b'+' || y == b'+' {
            if x == 0 {
                return -1;
            }
            if y == 0 {
                return 1;
            }
            if x != b'+' {
                return 1;
            }
            if y != b'+' {
                return -1;
            }
            one += 1;
            two += 1;
            continue;
        }
        if x == 0 || y == 0 {
            break;
        }
        let numeric = x.is_ascii_digit();
        let in_segment = |c: u8| if numeric { c.is_ascii_digit() } else { c.is_ascii_alphabetic() };
        let (mut end_one, mut end_two) = (one, two);
        while in_segment(at(a, end_one)) {
            end_one += 1;
        }
        while in_segment(at(b, end_two)) {
            end_two += 1;
        }
        if end_two == two {
            return if numeric { 1 } else { -1 };
        }
        if numeric {
            while one < end_one && a[one] == b'0' {
                one += 1;
            }
            while two < end_two && b[two] == b'0' {
                two += 1;
            }
            let (len_one, len_two) = (end_one - one, end_two - two);
            if len_one != len_two {
                return if len_one > len_two { 1 } else { -1 };
            }
        }
        match a[one..end_one].cmp(&b[two..end_two]) {
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Less => return -1,
            std::cmp::Ordering::Equal => {}
        }
        one = end_one;
        two = end_two;
    }
    match (at(a, one), at(b, two)) {
        (0, 0) => 0,
        (0, _) => -1,
        _ => 1,
    }
}

/// A file name split as blscfg.c's split_package_string splits it with a
/// name: release after the last '-', version after the last '-' before it,
/// name the rest; with one '-' the part after it is the version, with none
/// the whole is the name.
fn split_package_string(s: &[u8]) -> (&[u8], Option<&[u8]>, Option<&[u8]>) {
    let Some(last) = s.iter().rposition(|&c| c == b'-') else {
        return (s, None, None);
    };
    let (rest, release) = (&s[..last], &s[last + 1..]);
    match rest.iter().rposition(|&c| c == b'-') {
        Some(dash) => (&rest[..dash], Some(&rest[dash + 1..]), Some(release)),
        None => (rest, Some(release), None),
    }
}

/// blscfg.c's bls_cmp: the two entries' file names, less ".conf",
/// compared by name, then version, then release.
pub fn bls_cmp(a: &str, b: &str) -> i32 {
    let (name_a, version_a, release_a) = split_package_string(a.as_bytes());
    let (name_b, version_b, release_b) = split_package_string(b.as_bytes());
    [(name_a, name_b), (version_a.unwrap_or_default(), version_b.unwrap_or_default()),
        (release_a.unwrap_or_default(), release_b.unwrap_or_default())]
        .into_iter()
        .map(|(x, y)| vercmp(x, y))
        .find(|&order| order != 0)
        .unwrap_or(0)
}

/// Why check cannot tell the order blscfg lists the entries in.
#[derive(Debug, PartialEq)]
pub enum UnknownOrder {
    /// Two files compare as the same version, so bls_add_entry keeps the
    /// one GRUB reads first, in its directory's order, which check does not
    /// read.
    SameVersion(String, String),
    /// The comparison does not order these two as it orders the rest, so
    /// the order depends on the order GRUB reads them in.
    Unordered(String, String),
}

/// The order in which blscfg lists the entries whose file names, less
/// ".conf", are names, as indices into names: bls_add_entry inserts each
/// entry before the first one it is newer than, so the newest is listed
/// first (blscfg.c, bls_add_entry and bls_cmp). The result holds whatever
/// order GRUB reads the files in only when no two compare the same and
/// every entry is newer than each one after it.
pub fn blscfg_order(names: &[&str]) -> Result<Vec<usize>, UnknownOrder> {
    for (i, a) in names.iter().enumerate() {
        if let Some(b) = names[i + 1..].iter().find(|b| bls_cmp(a, b) == 0) {
            return Err(UnknownOrder::SameVersion(a.to_string(), b.to_string()));
        }
    }
    let mut order: Vec<usize> = Vec::with_capacity(names.len());
    for (i, name) in names.iter().enumerate() {
        let at = order.iter().position(|&e| bls_cmp(name, names[e]) == 1).unwrap_or(order.len());
        order.insert(at, i);
    }
    for (k, &a) in order.iter().enumerate() {
        if let Some(&b) = order[k + 1..].iter().find(|&&b| bls_cmp(names[a], names[b]) != 1) {
            return Err(UnknownOrder::Unordered(names[a].to_string(), names[b].to_string()));
        }
    }
    Ok(order)
}

/// The id create_entry gives the menu entry for the file whose name, less
/// ".conf", is name: name up to a ".conf" at its end. None where
/// create_entry never returns: its loop that strips ".conf" looks again
/// from the first ".conf" it finds, so a first ".conf" that is not at the
/// end is found forever (blscfg.c, create_entry; grub-core/kern/misc.c,
/// grub_strstr).
pub fn bls_menu_id(name: &str) -> Option<&str> {
    match name.find(".conf") {
        None => Some(name),
        Some(at) if at + ".conf".len() == name.len() => Some(&name[..at]),
        Some(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmp(a: &str, b: &str) -> i32 {
        vercmp(a.as_bytes(), b.as_bytes())
    }

    // Each case follows blscfg.c's vercmp line by line.
    #[test]
    fn vercmp_orders_as_rpm_does() {
        assert_eq!(cmp("1.0", "1.0"), 0);
        assert_eq!(cmp("2.0", "1.0"), 1);
        assert_eq!(cmp("1.0", "2.0"), -1);
        assert_eq!(cmp("1.10", "1.9"), 1);
        assert_eq!(cmp("1.01", "1.1"), 0);
        assert_eq!(cmp("1.0a", "1.0"), 1);
        assert_eq!(cmp("1.0~rc1", "1.0"), -1);
        assert_eq!(cmp("1.0+git", "1.0"), 1);
        assert_eq!(cmp("1.a", "1.1"), -1);
        assert_eq!(cmp("1.1", "1.a"), 1);
        assert_eq!(cmp("1_0", "1.0"), 0);
    }

    // Fedora names an entry <machine-id>-<kernel version>.conf, and the
    // rescue entry <machine-id>-0-rescue.conf (a Fedora 45 install's
    // /boot/loader/entries): the kernels come first, newest first, then
    // the rescue entry.
    #[test]
    fn blscfg_lists_fedoras_entries_newest_kernel_first() {
        let names = [
            "3f2a9c41-0-rescue",
            "3f2a9c41-6.19.9-200.fc45.x86_64",
            "3f2a9c41-7.2.11-300.fc45.x86_64",
        ];
        assert_eq!(blscfg_order(&names), Ok(vec![2, 1, 0]));
    }

    #[test]
    fn blscfg_order_is_unknown_for_names_of_the_same_version() {
        assert_eq!(blscfg_order(&["a-1.0-1", "b-1", "a-1.00-1"]),
            Err(UnknownOrder::SameVersion("a-1.0-1".into(), "a-1.00-1".into())));
    }

    #[test]
    fn create_entry_strips_one_trailing_conf_and_loops_on_another() {
        assert_eq!(bls_menu_id("abc-6.19.9"), Some("abc-6.19.9"));
        assert_eq!(bls_menu_id("abc.conf"), Some("abc"));
        assert_eq!(bls_menu_id("abc.confx"), None);
        assert_eq!(bls_menu_id("a.conf.conf"), None);
    }
}
