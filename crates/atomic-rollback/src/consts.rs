//! Shared constants used across multiple modules.

// Temporary mount point for the btrfs top-level subvolume.
pub const TOPLEVEL_MOUNT: &str = "/mnt/atomic-rollback-toplevel";

// Directory holding temporary mount points for probing filesystems. Only
// root can write to /run, so no other user can prepare an entry there.
pub const PROBE_MOUNT_PARENT: &str = "/run";

// mkdtemp(3) template for each probe mount point: the trailing XXXXXX is
// replaced with a unique suffix when the directory is created.
pub const PROBE_MOUNT_TEMPLATE: &str = "atomic-rollback-probe-XXXXXX";

// Btrfs top-level subvolume ID. Always 5 by definition.
// All user subvolumes (root, home, var) are children of this.
pub const BTRFS_TOPLEVEL_SUBVOLID: u64 = 5;

// Configuration file path. Shell key=value format.
pub const CONFIG_PATH: &str = "/etc/atomic-rollback.conf";

// Maximum number of automatic snapshots to retain. Overridden by
// MAX_SNAPSHOTS in CONFIG_PATH if present.
pub const MAX_SNAPSHOTS: usize = 50;
