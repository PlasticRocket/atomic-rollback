//! Filesystem entry swap via renameat2(RENAME_EXCHANGE). Every
//! irreversible operation in the tool (migration steps, rollback,
//! kernel hook) goes through this function.

use std::path::Path;

use crate::tools::SubvolName;

/// The exchange rollback makes in the top-level subvolume: the snapshot
/// takes the root subvolume's name and the root subvolume takes the
/// snapshot's, in one renameat2(RENAME_EXCHANGE) call.
#[derive(Clone)]
pub struct RenameExchange {
    /// The name fstab mounts as /, below the top-level subvolume.
    pub root: SubvolName,
    /// The snapshot's name, below the top-level subvolume.
    pub snapshot: SubvolName,
}

impl RenameExchange {
    /// Maps a path below the top-level subvolume, as it reads after the
    /// exchange, to the path naming the same file before it: a path through
    /// the root subvolume's name reaches the snapshot.
    pub fn before_exchange(&self, path: &str) -> String {
        let path = path.trim_start_matches('/');
        let root = self.root.as_str().trim_matches('/');
        let snapshot = self.snapshot.as_str().trim_matches('/');
        match below(path, root) {
            Some(rest) => format!("{snapshot}{rest}"),
            None => path.to_string(),
        }
    }
}

/// The rest of path after name, when path is name or lies below it.
fn below<'a>(path: &'a str, name: &str) -> Option<&'a str> {
    path.strip_prefix(name).filter(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// Swap two filesystem entries within the same directory.
/// Uses renameat2(RENAME_EXCHANGE).
/// On btrfs: single transaction (fs/btrfs/inode.c:8276).
/// On vfat: two separate directory entry writes
/// (fs/fat/namei_vfat.c:1097-1100). Each write is a complete
/// 32-byte entry (fs/fat/inode.c:887-906), so partial power
/// loss produces entries with consistent size and cluster fields.
#[cfg(target_os = "linux")]
pub fn rename_exchange(dir: &Path, a: &str, b: &str) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let dir_fd = std::fs::File::open(dir)
        .map_err(|e| format!("open {}: {e}", dir.display()))?;

    let a = CString::new(a).map_err(|e| format!("invalid name '{a}': {e}"))?;
    let b = CString::new(b).map_err(|e| format!("invalid name '{b}': {e}"))?;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            dir_fd.as_raw_fd(),
            a.as_ptr(),
            dir_fd.as_raw_fd(),
            b.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };

    if ret != 0 {
        let errno = std::io::Error::last_os_error();
        Err(format!("RENAME_EXCHANGE {}/{} <-> {}/{}: {errno}", dir.display(), a.to_string_lossy(), dir.display(), b.to_string_lossy()))
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn rename_exchange(_dir: &Path, _a: &str, _b: &str) -> Result<(), String> {
    unreachable!("atomic-rollback is a Linux-only tool")
}
