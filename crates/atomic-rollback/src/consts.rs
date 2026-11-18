//! Shared constants used across multiple modules.

// Temporary mount point for the btrfs top-level subvolume.
pub const TOPLEVEL_MOUNT: &str = "/mnt/atomic-rollback-toplevel";

// Directory holding the temporary mount points where filesystems are
// mounted for inspection. Only root can write to /run, so no other user can
// prepare an entry there.
pub const TEMPORARY_MOUNTPOINT_PARENT: &str = "/run";

// mkdtemp(3) template for each temporary mount point: the trailing XXXXXX
// is replaced with a unique suffix when the directory is created.
pub const TEMPORARY_MOUNTPOINT_TEMPLATE: &str = "atomic-rollback-mount-XXXXXX";

// Btrfs top-level subvolume ID. Always 5 by definition.
// All user subvolumes (root, home, var) are children of this.
pub const BTRFS_TOPLEVEL_SUBVOLID: u64 = 5;

// Inode number of the root directory of every Btrfs subvolume
// (BTRFS_FIRST_FREE_OBJECTID, include/uapi/linux/btrfs_tree.h).
#[cfg(target_os = "linux")]
pub const BTRFS_FIRST_FREE_OBJECTID: u64 = 256;

// Configuration file path. Shell key=value format.
pub const CONFIG_PATH: &str = "/etc/atomic-rollback.conf";

// Maximum number of automatic snapshots to retain. Overridden by
// MAX_SNAPSHOTS in CONFIG_PATH if present.
pub const MAX_SNAPSHOTS: usize = 50;
