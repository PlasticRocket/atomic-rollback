//! The disk space check before an RPM transaction on a Btrfs root.
//!
//! The snapshot taken before the transaction keeps every file the
//! transaction replaces or erases, so their blocks stay in use while it
//! runs. rpm's own check (rpm 6.1.0 lib/transaction.cc) credits replaced
//! files to the packages installed after them (rpmtsUpdateDSI and
//! rpmtsCheckDSIProblems) and counts each device number apart
//! (rpmtsCreateDSI), while Btrfs gives every subvolume its own: with a
//! snapshot kept, it approves transactions that fail part way with ENOSPC.
//! This check runs before the snapshot and counts as libzypp's growonly and
//! garuda-update count: every file of every package the transaction
//! installs, here those landing on the Btrfs filesystem holding `/`,
//! crediting nothing. It rounds sizes and adds the margin as rpm does.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::tools;

// rpm's margin on the blocks needed, adj_fs_blocks (transaction.cc:55).
const MARGIN_NUMERATOR: u64 = 21;
const MARGIN_DENOMINATOR: u64 = 20;

// rpm's block size when statvfs reports none (transaction.cc:145-147).
const DEFAULT_BLOCK_SIZE: u64 = 512;

// Largest block size rpm accounts in (transaction.cc:163-171).
const MAX_BLOCK_SIZE: u64 = 4096;

// Separators of the RPM plugin's records: fields, then records.
const FIELD_SEPARATOR: u8 = b'\t';
const RECORD_TERMINATOR: u8 = 0;
const FIELDS_PER_RECORD: usize = 4;

/// One file of a package the transaction installs, as the RPM plugin reads
/// it through rpm's public API.
#[derive(Debug, PartialEq)]
pub struct PackageFile {
    /// Position of the file in its package's file list.
    index: u32,
    /// Position of the last file of its hard-link set (rpmfilesFLinks), or
    /// its own position when it has no hard links.
    hard_link_last: u32,
    /// rpmfilesFSize.
    size: u64,
    /// rpmfilesFN under the transaction's root directory.
    path: PathBuf,
}

/// Parses the RPM plugin's records, one per file, each
/// "index\thard_link_last\tsize\tpath" ended by a NUL byte. The path is
/// the last field and may hold any byte but NUL.
pub fn parse_package_files(input: &[u8]) -> Result<Vec<PackageFile>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let records = input.strip_suffix(&[RECORD_TERMINATOR])
        .ok_or("the last record has no terminating NUL")?;
    records.split(|&b| b == RECORD_TERMINATOR).map(parse_record).collect()
}

fn parse_record(record: &[u8]) -> Result<PackageFile, String> {
    let fields: Vec<&[u8]> = record.splitn(FIELDS_PER_RECORD, |&b| b == FIELD_SEPARATOR).collect();
    let [index, hard_link_last, size, path] = fields[..] else {
        return Err(format!("malformed record: {}", String::from_utf8_lossy(record)));
    };
    if path.is_empty() {
        return Err(format!("record without a path: {}", String::from_utf8_lossy(record)));
    }
    Ok(PackageFile {
        index: number(index)?,
        hard_link_last: number(hard_link_last)?,
        size: number(size)?,
        path: PathBuf::from(OsStr::from_bytes(path)),
    })
}

fn number<T: std::str::FromStr>(field: &[u8]) -> Result<T, String> {
    std::str::from_utf8(field).ok()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("not a number: {}", String::from_utf8_lossy(field)))
}

/// The units rpm accounts a filesystem's space in (rpmtsCreateDSI,
/// transaction.cc:145-171): block size, and available blocks of that size.
#[derive(Debug, PartialEq)]
pub struct Accounting {
    block_size: u64,
    available_blocks: u64,
}

/// rpm's units from statvfs: f_bsize, 512 when zero; above 4096, blocks
/// of 4096 holding the same available bytes.
pub fn accounting(f_bsize: u64, f_bavail: u64) -> Accounting {
    let block_size = if f_bsize == 0 { DEFAULT_BLOCK_SIZE } else { f_bsize };
    if block_size > MAX_BLOCK_SIZE {
        Accounting {
            block_size: MAX_BLOCK_SIZE,
            available_blocks: f_bavail.saturating_mul(block_size) / MAX_BLOCK_SIZE,
        }
    } else {
        Accounting { block_size, available_blocks: f_bavail }
    }
}

/// Blocks the files need on the root filesystem: every file whose
/// directory lies on it, its size rounded up to whole blocks as rpm's
/// BLOCK_ROUND does (transaction.cc:56), each hard-link set once through
/// its last file as rpm counts it (transaction.cc:698-704), nothing
/// credited. on_root_filesystem says whether a directory lies on it.
pub fn blocks_needed(
    files: &[PackageFile],
    block_size: u64,
    mut on_root_filesystem: impl FnMut(&Path) -> Result<bool, String>,
) -> Result<u64, String> {
    let mut blocks: u64 = 0;
    for file in files {
        if file.index != file.hard_link_last {
            continue;
        }
        let dir = file.path.parent().unwrap_or(&file.path);
        if on_root_filesystem(dir)? {
            blocks = blocks.saturating_add(file.size.div_ceil(block_size));
        }
    }
    Ok(blocks)
}

/// A transaction whose files do not fit: what they write, what that needs
/// with rpm's margin, and what is free, in bytes.
#[derive(Debug, PartialEq)]
pub struct Shortfall {
    writes: u64,
    needed: u64,
    free: u64,
}

/// Whether blocks fit the available space once rpm's margin is added, the
/// comparison rpm makes (rpmtsCheckDSIProblems, transaction.cc:262).
pub fn shortfall(blocks: u64, space: &Accounting) -> Option<Shortfall> {
    let with_margin = blocks.saturating_mul(MARGIN_NUMERATOR) / MARGIN_DENOMINATOR;
    (with_margin > space.available_blocks).then(|| Shortfall {
        writes: blocks.saturating_mul(space.block_size),
        needed: with_margin.saturating_mul(space.block_size),
        free: space.available_blocks.saturating_mul(space.block_size),
    })
}

impl fmt::Display for Shortfall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "atomic-rollback: not enough free space for this transaction and the snapshot taken before it.")?;
        writeln!(f, "The packages it installs write {} to the Btrfs filesystem mounted at /, which with rpm's 5% margin needs {}; {} is free.",
            amount(self.writes), amount(self.needed), amount(self.free))?;
        writeln!(f, "The snapshot keeps the old copy of every file the transaction replaces or removes, so none of that space comes back while it runs.")?;
        writeln!(f, "Free space on that filesystem, for example by deleting snapshots no longer needed, then run the transaction again:")?;
        writeln!(f, "  atomic-rollback snapshot list")?;
        writeln!(f, "  atomic-rollback snapshot delete <N>")?;
        write!(f, "Btrfs frees a deleted snapshot's space in the background.")
    }
}

/// bytes in the largest binary unit that keeps a whole part, followed by
/// the exact count.
fn amount(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    const STEP: f64 = 1024.0;
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= STEP && unit < UNITS.len() - 1 {
        value /= STEP;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} bytes")
    } else {
        format!("{value:.2} {} ({bytes} bytes)", UNITS[unit])
    }
}

/// Refuses a transaction whose files do not fit beside its snapshot: the
/// blocks they need on the Btrfs filesystem holding `/`, with rpm's
/// margin, against that filesystem's available space. The error is the
/// shortfall's message, or why the check could not run.
pub fn check(files: &[PackageFile]) -> Result<(), String> {
    let root = tools::btrfs_fsid(Path::new("/"))
        .map_err(|e| format!("cannot read the filesystem of /: {e}"))?
        .ok_or("/ is not on Btrfs")?;
    let free = tools::statvfs("/")?;
    let space = accounting(free.f_bsize, free.f_bavail);

    let mut placed: HashMap<PathBuf, bool> = HashMap::new();
    let blocks = blocks_needed(files, space.block_size, |dir| {
        if let Some(&on_root) = placed.get(dir) {
            return Ok(on_root);
        }
        let existing = nearest_directory(dir);
        let fsid = tools::btrfs_fsid(existing)
            .map_err(|e| format!("cannot read the filesystem of {}: {e}", existing.display()))?;
        let on_root = fsid == Some(root);
        placed.insert(dir.to_path_buf(), on_root);
        Ok(on_root)
    })?;

    match shortfall(blocks, &space) {
        Some(short) => Err(short.to_string()),
        None => Ok(()),
    }
}

/// The directory a file under dir lands in: dir, or its nearest existing
/// ancestor when the transaction creates dir, following symbolic links.
fn nearest_directory(dir: &Path) -> &Path {
    let mut dir = dir;
    while !dir.is_dir() {
        match dir.parent() {
            Some(parent) => dir = parent,
            None => break,
        }
    }
    dir
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "/";

    fn file(index: u32, hard_link_last: u32, size: u64, path: &str) -> PackageFile {
        PackageFile { index, hard_link_last, size, path: PathBuf::from(path) }
    }

    // The root Btrfs filesystem holds everything but /boot/efi.
    fn on_root(dir: &Path) -> Result<bool, String> {
        Ok(!dir.starts_with("/boot/efi"))
    }

    fn need(files: &[PackageFile], block_size: u64) -> u64 {
        blocks_needed(files, block_size, on_root).unwrap()
    }

    // --- records ---

    #[test]
    fn records_parse_into_package_files() {
        let input = b"0\t0\t2147483648\t/usr/share/a.bin\x001\t2\t17\t/usr/bin/tool\x00";
        assert_eq!(parse_package_files(input).unwrap(), vec![
            file(0, 0, 2147483648, "/usr/share/a.bin"),
            file(1, 2, 17, "/usr/bin/tool"),
        ]);
        assert_eq!(parse_package_files(b"").unwrap(), vec![]);
    }

    #[test]
    fn records_keep_every_path_byte_but_nul() {
        let input = b"0\t0\t5\t/usr/share/a\tb\nc\xff\x00";
        let files = parse_package_files(input).unwrap();
        assert_eq!(files[0].path.as_os_str().as_bytes(), b"/usr/share/a\tb\nc\xff");
    }

    #[test]
    fn records_refuse_a_truncated_or_malformed_input() {
        assert!(parse_package_files(b"0\t0\t5\t/usr/share/a").is_err());
        assert!(parse_package_files(b"0\t0\t/usr/share/a\x00").is_err());
        assert!(parse_package_files(b"0\t0\t-5\t/usr/share/a\x00").is_err());
        assert!(parse_package_files(b"0\t0\t5\t\x00").is_err());
    }

    // --- rpm's units ---

    #[test]
    fn accounting_uses_rpm_block_size() {
        assert_eq!(accounting(4096, 786432), Accounting { block_size: 4096, available_blocks: 786432 });
        assert_eq!(accounting(0, 100), Accounting { block_size: 512, available_blocks: 100 });
        assert_eq!(accounting(65536, 10), Accounting { block_size: 4096, available_blocks: 160 });
    }

    // --- the need ---

    #[test]
    fn need_rounds_each_file_up_to_whole_blocks() {
        let files = [
            file(0, 0, 0, "/usr/share/p/empty"),
            file(1, 1, 1, "/usr/share/p/one"),
            file(2, 2, 4096, "/usr/share/p/block"),
            file(3, 3, 4097, "/usr/share/p/block-and-one"),
        ];
        // 0, 1, 1 and 2 blocks.
        assert_eq!(need(&files, 4096), 4);
    }

    #[test]
    fn need_counts_a_hard_link_set_once() {
        // Three names of one 10000-byte file; rpm counts the last.
        let files = [
            file(0, 2, 10000, "/usr/bin/a"),
            file(1, 2, 10000, "/usr/bin/b"),
            file(2, 2, 10000, "/usr/bin/c"),
            file(3, 3, 10000, "/usr/bin/d"),
        ];
        assert_eq!(need(&files, 4096), 3 + 3);
    }

    #[test]
    fn need_leaves_out_files_on_other_filesystems() {
        let files = [
            file(0, 0, 8192, "/usr/lib/modules/6.17/vmlinuz"),
            file(1, 1, 40960, "/boot/efi/EFI/fedora/grubx64.efi"),
        ];
        assert_eq!(need(&files, 4096), 2);
    }

    // A directory entry lands in its parent directory, as rpm's
    // fingerprints place every file by its directory.
    #[test]
    fn need_places_each_file_by_its_directory() {
        let mut asked = Vec::new();
        let files = [file(0, 0, 4096, "/boot/efi"), file(1, 1, 4096, ROOT)];
        let blocks = blocks_needed(&files, 4096, |dir| {
            asked.push(dir.to_path_buf());
            on_root(dir)
        }).unwrap();
        assert_eq!(blocks, 2);
        assert_eq!(asked, vec![PathBuf::from("/boot"), PathBuf::from(ROOT)]);
    }

    #[test]
    fn need_fails_when_a_directory_cannot_be_placed() {
        let files = [file(0, 0, 1, "/usr/share/a")];
        assert!(blocks_needed(&files, 4096, |_| Err("EIO".to_string())).is_err());
    }

    // --- the refusal ---

    #[test]
    fn shortfall_applies_rpm_margin_in_blocks() {
        let space = Accounting { block_size: 4096, available_blocks: 19 };
        // 19 * 21 / 20 = 19 in rpm's integer arithmetic: it fits.
        assert_eq!(shortfall(19, &space), None);
        // 20 * 21 / 20 = 21 > 20.
        let space = Accounting { block_size: 4096, available_blocks: 20 };
        assert_eq!(shortfall(20, &space), Some(Shortfall { writes: 20 * 4096, needed: 21 * 4096, free: 20 * 4096 }));
        let space = Accounting { block_size: 4096, available_blocks: 21 };
        assert_eq!(shortfall(20, &space), None);
    }

    // The run-2 transaction: two packages each replacing a 2 GiB file,
    // 3 GiB free. Nothing replaced is credited, so it needs 4.2 GiB.
    #[test]
    fn shortfall_refuses_replacing_more_than_is_free() {
        let blocks = 2 * ((2 << 30) / 4096);
        let space = accounting(4096, (3 << 30) / 4096);
        let short = shortfall(blocks, &space).unwrap();
        assert_eq!((short.writes, short.free), (4 << 30, 3 << 30));
        assert_eq!(short.needed, blocks * 21 / 20 * 4096);
    }

    #[test]
    fn shortfall_message_states_amounts_and_how_to_free_space() {
        let message = Shortfall { writes: 4294967296, needed: 4509715660, free: 3221225472 }.to_string();
        for expected in ["4294967296", "4509715660", "3221225472",
                         "atomic-rollback snapshot list", "atomic-rollback snapshot delete <N>"] {
            assert!(message.contains(expected), "{expected} missing from:\n{message}");
        }
    }
}
