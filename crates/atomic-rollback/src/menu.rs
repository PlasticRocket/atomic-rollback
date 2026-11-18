//! GRUB's boot menu: the entries Fedora's blscfg adds from the BLS
//! directory and the order it adds them in (Fedora's grub2 2.12 patches,
//! grub-core/commands/blscfg.c), and the entry normal mode boots when no
//! key is pressed (grub-core/normal/menu.c, run_menu).

use crate::grub::{grub_strtoull, is_grub_space, BASE_FROM_PREFIX};

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

/// menuentry_eq (normal/menu.c): whether spec names the menu entry whose
/// id or title is id. A '>' in spec ends the part naming an entry, and '>>'
/// stands for '>'; with limit, spec may go on after limit bytes with a
/// space.
fn menuentry_eq(id: &[u8], spec: &[u8], limit: Option<usize>) -> bool {
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let (mut p1, mut p2) = (0, 0);
    while limit.is_none_or(|l| p1 <= l) {
        if at(spec, p2) == b'>' && at(spec, p2 + 1) != b'>' {
            return at(id, p1) == 0 && p2 != 0;
        }
        if at(spec, p2) == b'>' {
            p2 += 1;
        }
        if at(id, p1) != at(spec, p2) {
            // menu.c returns p1 - 1 here, which is true unless p1 is 1.
            return limit == Some(p1) && at(id, p1) == 0 && is_grub_space(at(spec, p2)) && p1 != 1;
        }
        if at(id, p1) == 0 {
            return p1 != 0;
        }
        p1 += 1;
        p2 += 1;
    }
    false
}

/// An entry of the menu, as menu.c matches default against it.
#[derive(Debug, Clone)]
pub struct MenuItem {
    pub id: String,
    pub title: String,
}

/// An entry a script adds after blscfg: its id and title where check can
/// read them from the menuentry line, and whether it is added on every
/// run, not inside a condition or loop.
#[derive(Debug, Clone)]
pub struct AddedEntry {
    pub id: Option<String>,
    pub title: Option<String>,
    pub certain: bool,
}

/// The entries scripts add after blscfg, in order. countable is false
/// when one is added inside a loop, any number of times.
#[derive(Debug, Clone)]
pub struct AddedEntries {
    pub entries: Vec<AddedEntry>,
    pub countable: bool,
}

/// An entry normal mode may boot by default.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Pick {
    /// The entry at this index among the entries blscfg adds, which come
    /// first in the menu.
    Bls(usize),
    /// An entry a script adds after blscfg.
    Added,
}

/// Whether an entry check reads only in part matches: Some(answer), or
/// None when it cannot tell.
fn matches(text: Option<&str>, spec: &[u8], limit: Option<usize>) -> Option<bool> {
    text.map(|text| menuentry_eq(text.as_bytes(), spec, limit))
}

/// The entries normal mode may boot without a key press, given default,
/// the default variable when the menu runs, over a menu of bls followed by
/// added (normal/menu.c). run_menu boots entry get_entry_number(default),
/// or the first entry when that is negative or past the menu's end.
/// get_entry_number_helper matches default's first word against each
/// entry's id, then all of default against each title, then reads it as a
/// number (grub_strtoul with base 0, taken as an int); get_entry_number
/// refuses anything after an id or a number. More than one pick means the
/// added entries' presence or names decide; bls holds at least one entry.
pub fn default_picks(default: Option<&str>, bls: &[MenuItem], added: &AddedEntries) -> Vec<Pick> {
    let first = Pick::Bls(0);
    let Some(spec) = default.map(str::as_bytes) else {
        return vec![first];
    };
    let mut picks: Vec<Pick> = Vec::new();
    fn pick(picks: &mut Vec<Pick>, p: Pick) {
        if !picks.contains(&p) {
            picks.push(p);
        }
    }

    let word = spec.iter().position(|&c| is_grub_space(c)).unwrap_or(spec.len());
    let by_id = |entry: Pick| if word == spec.len() { entry } else { first };
    if let Some(i) = bls.iter().position(|e| menuentry_eq(e.id.as_bytes(), spec, Some(word))) {
        return vec![by_id(Pick::Bls(i))];
    }
    for entry in &added.entries {
        match matches(entry.id.as_deref(), spec, Some(word)) {
            Some(false) => {}
            found => {
                pick(&mut picks, by_id(Pick::Added));
                if found == Some(true) && entry.certain {
                    return picks;
                }
            }
        }
    }

    if let Some(i) = bls.iter().position(|e| menuentry_eq(e.title.as_bytes(), spec, None)) {
        pick(&mut picks, Pick::Bls(i));
        return picks;
    }
    for entry in &added.entries {
        match matches(entry.title.as_deref(), spec, None) {
            Some(false) => {}
            found => {
                pick(&mut picks, Pick::Added);
                if found == Some(true) && entry.certain {
                    return picks;
                }
            }
        }
    }

    let mut end = 0;
    let index = match grub_strtoull(spec, &mut end, BASE_FROM_PREFIX) {
        // (int) of the unsigned long: its low 32 bits.
        Some(number) if end == spec.len() => i64::from(number as u32 as i32),
        _ => -1,
    };
    let certain_size = bls.len() + added.entries.iter().filter(|e| e.certain).count();
    let largest_size = bls.len() + added.entries.len();
    match usize::try_from(index) {
        Ok(i) if i < bls.len() => pick(&mut picks, Pick::Bls(i)),
        Ok(i) if i < certain_size => pick(&mut picks, Pick::Added),
        Ok(i) if i < largest_size || !added.countable => {
            pick(&mut picks, Pick::Added);
            pick(&mut picks, first);
        }
        _ => pick(&mut picks, first),
    }
    picks
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

    fn items(ids_titles: &[(&str, &str)]) -> Vec<MenuItem> {
        ids_titles.iter().map(|(id, title)| MenuItem { id: id.to_string(), title: title.to_string() }).collect()
    }

    fn none_added() -> AddedEntries {
        AddedEntries { entries: Vec::new(), countable: true }
    }

    fn firmware(certain: bool) -> AddedEntries {
        AddedEntries {
            entries: vec![AddedEntry {
                id: Some("uefi-firmware".into()),
                title: Some("UEFI Firmware Settings".into()),
                certain,
            }],
            countable: true,
        }
    }

    // normal/menu.c, get_entry_number_helper and run_menu.
    #[test]
    fn default_is_matched_by_id_then_title_then_number() {
        let bls = items(&[("k7", "Fedora 7"), ("k6", "Fedora 6"), ("rescue", "Rescue")]);
        let picks = |default: Option<&str>| default_picks(default, &bls, &firmware(false));
        assert_eq!(picks(None), vec![Pick::Bls(0)]);
        assert_eq!(picks(Some("k6")), vec![Pick::Bls(1)]);
        assert_eq!(picks(Some("Rescue")), vec![Pick::Bls(2)]);
        assert_eq!(picks(Some("2")), vec![Pick::Bls(2)]);
        assert_eq!(picks(Some("0x1")), vec![Pick::Bls(1)]);
        // A saved entry whose file is gone matches nothing.
        assert_eq!(picks(Some("k5")), vec![Pick::Bls(0)]);
        assert_eq!(picks(Some("")), vec![Pick::Bls(0)]);
        // Anything after the id or the number refuses it.
        assert_eq!(picks(Some("k6 extra")), vec![Pick::Bls(0)]);
        assert_eq!(picks(Some("1 ")), vec![Pick::Bls(0)]);
        // A submenu path names its first entry.
        assert_eq!(picks(Some("k6>anything")), vec![Pick::Bls(1)]);
        // An int: 2^32 + 1 is 1.
        assert_eq!(picks(Some("4294967297")), vec![Pick::Bls(1)]);
    }

    #[test]
    fn default_past_the_boot_entries_depends_on_the_added_entries() {
        let bls = items(&[("k7", "Fedora 7")]);
        assert_eq!(default_picks(Some("uefi-firmware"), &bls, &firmware(true)), vec![Pick::Added]);
        assert_eq!(default_picks(Some("uefi-firmware"), &bls, &firmware(false)), vec![Pick::Added, Pick::Bls(0)]);
        assert_eq!(default_picks(Some("1"), &bls, &firmware(true)), vec![Pick::Added]);
        assert_eq!(default_picks(Some("1"), &bls, &firmware(false)), vec![Pick::Added, Pick::Bls(0)]);
        assert_eq!(default_picks(Some("2"), &bls, &firmware(false)), vec![Pick::Bls(0)]);
        assert_eq!(default_picks(Some("1"), &bls, &none_added()), vec![Pick::Bls(0)]);
    }
}
