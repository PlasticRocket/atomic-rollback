//! GRUB path resolution. check verifies the boot chain as GRUB walks it:
//! the ESP stub names a filesystem and a prefix, grub.cfg and grubenv sit
//! under the prefix, grubenv's blsdir names the BLS directory, and each
//! BLS entry names a kernel and initramfs. This module translates those
//! GRUB paths into the Linux paths where the same files are visible.
//!
//! On Btrfs, GRUB's driver resolves an absolute path from the top-level
//! subvolume (ID 5) unless btrfs_relative_path is set, and from the
//! default subvolume when it is (grub-core/fs/btrfs.c, find_path).
//! Neither is necessarily the subvolume Linux mounts at /.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::consts::TOPLEVEL_MOUNT;
use crate::platform::FEDORA as P;
use crate::tools;

/// BLS directory blscfg scans when the blsdir variable is unset
/// (grub-core/commands/blscfg.c, GRUB_BLS_CONFIG_PATH).
const BLS_DEFAULT_DIR: &str = "/loader/entries";

/// Directory blscfg scans when listing the first one fails, if blscfg was
/// called without an argument, as Fedora's grub.cfg calls it
/// (grub-core/commands/blscfg.c, find_entry).
const BLS_FALLBACK_DIR: &str = "/boot/loader/entries";

/// Errors from building a GrubContext. Distinguishes a missing privilege
/// (non-root invocation) from other errors, so the caller can surface
/// "try sudo" vs a real boot-chain problem.
pub enum GrubContextError {
    /// Reading the root-only ESP grub.cfg, or mounting the Btrfs
    /// top-level subvolume, was refused.
    PermissionDenied { reason: String },
    Other(String),
}

impl From<String> for GrubContextError {
    fn from(s: String) -> Self { GrubContextError::Other(s) }
}

/// The rename a pending rollback performs: RENAME_EXCHANGE gives the
/// snapshot the root subvolume's name, so after the swap GRUB reaches the
/// snapshot through every path that starts with the root subvolume.
pub struct PendingSwap {
    pub root: tools::SubvolName,
    pub snapshot: tools::SubvolName,
}

impl PendingSwap {
    /// Maps a path relative to the top-level subvolume, as GRUB will walk
    /// it after the swap, to the path naming the same file before it.
    fn before_swap(&self, path: &str) -> String {
        let root = self.root.as_str().trim_matches('/');
        let snapshot = self.snapshot.as_str().trim_matches('/');
        match path.strip_prefix(root) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => format!("{snapshot}{rest}"),
            _ => path.to_string(),
        }
    }
}

/// Where GRUB starts resolving an absolute path, and the Linux directory
/// where that starting point is visible.
pub enum Base {
    /// Not Btrfs: the filesystem's root, at this mount point.
    FilesystemRoot(PathBuf),
    /// Btrfs, btrfs_relative_path not set: the top-level subvolume,
    /// mounted here. swap is set when checking a snapshot before rollback.
    BtrfsTopLevel { toplevel: PathBuf, swap: Option<PendingSwap> },
    /// Btrfs, btrfs_relative_path set: the default subvolume, whose
    /// directory is this.
    BtrfsDefaultSubvol(PathBuf),
}

impl Base {
    /// Selects GRUB's starting point on the filesystem the ESP stub names.
    /// fs_root is where that filesystem's root is mounted; on Btrfs the
    /// root is the top-level subvolume. default_subvol yields the default
    /// subvolume's path below the top level and is called only when GRUB
    /// starts there.
    pub fn select(
        fstype: &tools::FsType,
        btrfs_relative: bool,
        fs_root: PathBuf,
        default_subvol: impl FnOnce() -> Result<String, String>,
    ) -> Result<Self, String> {
        Ok(match fstype {
            tools::FsType::Btrfs if btrfs_relative => Base::BtrfsDefaultSubvol(fs_root.join(default_subvol()?)),
            tools::FsType::Btrfs => Base::BtrfsTopLevel { toplevel: fs_root, swap: None },
            _ => Base::FilesystemRoot(fs_root),
        })
    }

    /// Selects GRUB's starting point as it will be once rollback has
    /// swapped in the snapshot at snapshot_root. fs_root is where the root
    /// of the filesystem the ESP stub names is mounted; on Btrfs that is
    /// the top-level subvolume, and snapshot_root lies below it.
    /// root_subvol yields the name fstab mounts as /, which the snapshot
    /// takes in the swap; it is called only when GRUB starts at the top
    /// level, where paths name subvolumes.
    pub fn after_rollback(
        fstype: &tools::FsType,
        btrfs_relative: bool,
        fs_root: PathBuf,
        snapshot_root: &Path,
        root_subvol: impl FnOnce() -> Result<tools::SubvolName, String>,
    ) -> Result<Self, String> {
        Ok(match fstype {
            // After the swap, rollback sets the snapshot as the default subvolume.
            tools::FsType::Btrfs if btrfs_relative => Base::BtrfsDefaultSubvol(snapshot_root.to_path_buf()),
            tools::FsType::Btrfs => {
                let snapshot = snapshot_root.strip_prefix(&fs_root).map_err(|_| format!(
                    "snapshot {} is not under the top-level subvolume mount {}",
                    snapshot_root.display(), fs_root.display()))?;
                let swap = PendingSwap {
                    root: root_subvol()?,
                    snapshot: tools::SubvolName::new(snapshot.to_string_lossy().into_owned()),
                };
                Base::BtrfsTopLevel { toplevel: fs_root, swap: Some(swap) }
            }
            // A separate boot filesystem is outside the snapshot, and
            // rollback leaves it as it is.
            _ => Base::FilesystemRoot(fs_root),
        })
    }

    /// Names the starting point for check's output.
    pub fn describe(&self) -> &'static str {
        match self {
            Base::FilesystemRoot(_) => "the root of the boot filesystem (not Btrfs)",
            Base::BtrfsTopLevel { .. } => "the Btrfs top-level subvolume (btrfs_relative_path not set)",
            Base::BtrfsDefaultSubvol(_) => "the Btrfs default subvolume (btrfs_relative_path set)",
        }
    }

    /// Translates a GRUB path into the Linux path of the file GRUB reads.
    /// GRUB skips leading slashes and walks the rest from its starting point.
    pub fn resolve(&self, grub_path: &str) -> PathBuf {
        let path = grub_path.trim_start_matches('/');
        match self {
            Base::FilesystemRoot(dir) | Base::BtrfsDefaultSubvol(dir) => dir.join(path),
            Base::BtrfsTopLevel { toplevel, swap: None } => toplevel.join(path),
            Base::BtrfsTopLevel { toplevel, swap: Some(swap) } => toplevel.join(swap.before_swap(path)),
        }
    }
}

/// Captures how GRUB resolves paths on the filesystem the ESP stub names.
/// Used by check.rs to verify that GRUB can find its configuration, its
/// boot entries, and the kernels they name.
pub struct GrubContext {
    pub base: Base,
    /// The ESP stub's prefix path. GRUB loads grub.cfg and grubenv from it.
    prefix: String,
    // Never read directly. Present so that a mount made for the check is
    // unmounted when GrubContext is dropped (Rust Drop convention).
    _mount: Option<tools::MountPoint>,
}

fn read_esp_stub(path: &Path) -> Result<tools::EspStub, GrubContextError> {
    let content = fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => GrubContextError::PermissionDenied {
            reason: format!("permission denied reading {}", path.display()),
        },
        _ => GrubContextError::Other(format!("cannot read ESP grub.cfg: {e}")),
    })?;
    reject_subvol_override(&content)?;
    Ok(tools::parse_esp_stub(&content)?)
}

/// Variables that point GRUB's Btrfs driver at a named subvolume
/// (grub-core/fs/btrfs.c, btrfs_handle_subvol). Neither Fedora's
/// gen_grub_cfgstub nor migrate writes them.
const SUBVOL_OVERRIDES: [&str; 2] = ["btrfs_subvol", "btrfs_subvolid"];

/// Refuses a stub that sets a subvolume override: check does not model
/// where GRUB resolves paths under one.
fn reject_subvol_override(content: &str) -> Result<(), String> {
    match SUBVOL_OVERRIDES.into_iter()
        .find(|name| content.lines().any(|line| tools::grub_assignment(line, name).is_some()))
    {
        Some(name) => Err(format!(
            "ESP grub.cfg sets {name}, which neither Fedora nor atomic-rollback writes. \
             check cannot tell which subvolume GRUB resolves paths from")),
        None => Ok(()),
    }
}

impl GrubContext {
    /// A context over directories already in place, with nothing mounted.
    #[cfg(test)]
    pub fn new(base: Base, prefix: String) -> Self {
        Self { base, prefix, _mount: None }
    }

    /// Builds a context from the live system's ESP grub.cfg. On Btrfs,
    /// mounts the top-level subvolume read-only for the context's lifetime;
    /// otherwise uses the filesystem's mount point, probe-mounting it if
    /// needed.
    pub fn from_system(root: &Path) -> Result<Self, GrubContextError> {
        let stub = read_esp_stub(&root.join(&P.esp_dir[1..]).join("grub.cfg"))?;
        let fstype = boot_fstype(&stub)?;

        let mount = if fstype == tools::FsType::Btrfs {
            if !tools::is_root() {
                return Err(GrubContextError::PermissionDenied {
                    reason: "mounting the Btrfs top-level subvolume requires root".into(),
                });
            }
            tools::mount_toplevel_ro(&stub.boot_uuid)?
        } else {
            tools::get_mount_point(&stub.boot_uuid.clone().into_device_spec())?
        };

        let base = Base::select(&fstype, stub.btrfs_relative, PathBuf::from(mount.path()),
            || tools::btrfs_subvol_get_default(mount.path()).map(|d| d.path().to_string()))?;

        Ok(Self { base, prefix: stub.grub_dir, _mount: Some(mount) })
    }

    /// Builds a context for verifying a snapshot before rollback. Reads the
    /// ESP config from the live system (the ESP is vfat, not in the
    /// snapshot). snapshot_root is the snapshot's directory under the
    /// top-level subvolume, which rollback has mounted at TOPLEVEL_MOUNT.
    /// A boot filesystem other than Btrfs is outside the snapshot, so its
    /// live mount point is used, probe-mounting it if needed.
    pub fn for_snapshot(snapshot_root: &Path) -> Result<Self, GrubContextError> {
        let stub = read_esp_stub(&Path::new(P.esp_dir).join("grub.cfg"))?;
        let fstype = boot_fstype(&stub)?;

        let mount = if fstype == tools::FsType::Btrfs {
            None
        } else {
            Some(tools::get_mount_point(&stub.boot_uuid.clone().into_device_spec())?)
        };
        let fs_root = mount.as_ref()
            .map_or_else(|| PathBuf::from(TOPLEVEL_MOUNT), |m| PathBuf::from(m.path()));

        let base = Base::after_rollback(&fstype, stub.btrfs_relative, fs_root, snapshot_root,
            live_root_subvol)?;

        Ok(Self { base, prefix: stub.grub_dir, _mount: mount })
    }

    pub fn resolve(&self, grub_path: &str) -> PathBuf {
        self.base.resolve(grub_path)
    }

    /// GRUB path of a file in the stub's prefix directory.
    pub fn prefix_path(&self, file: &str) -> String {
        format!("{}/{file}", self.prefix.trim_end_matches('/'))
    }

    /// Returns Ok if the GRUB path resolves to an existing file on disk.
    pub fn check_path_exists(&self, grub_path: &str) -> Result<(), String> {
        let linux_path = self.resolve(grub_path);
        if linux_path.exists() {
            Ok(())
        } else {
            Err(format!("'{grub_path}' resolves to '{}', not found", linux_path.display()))
        }
    }

    /// The Linux path of the directory blscfg reads boot entries from.
    /// blscfg scans the blsdir variable, which grub.cfg loads from
    /// $prefix/grubenv (util/grub.d/00_header.in), or BLS_DEFAULT_DIR when
    /// it is unset, then BLS_FALLBACK_DIR if listing that fails.
    pub fn bls_dir(&self) -> Result<PathBuf, String> {
        // A grubenv GRUB cannot read loads nothing, as when it is absent.
        let grubenv = fs::read_to_string(self.resolve(&self.prefix_path("grubenv"))).ok();
        let blsdir = grubenv.as_deref()
            .and_then(|env| grubenv_value(env, "blsdir"))
            .unwrap_or(BLS_DEFAULT_DIR);

        let mut tried = Vec::new();
        for dir in [blsdir, BLS_FALLBACK_DIR] {
            let linux_path = self.resolve(dir);
            if fs::read_dir(&linux_path).is_ok() {
                return Ok(linux_path);
            }
            tried.push(format!("'{dir}' (resolves to '{}')", linux_path.display()));
        }
        Err(format!("GRUB finds no boot entry directory: tried {}", tried.join(" and ")))
    }
}

/// The type of the filesystem the stub's search --fs-uuid names. GRUB's
/// resolution depends on it, so an unknown type is an error, not a guess.
fn boot_fstype(stub: &tools::EspStub) -> Result<tools::FsType, String> {
    tools::blkid_fstype(&stub.boot_uuid).map_err(|e| format!(
        "cannot determine the filesystem type of UUID={}: {e}", stub.boot_uuid.as_str()))
}

/// The subvolume the live fstab mounts as /, whose name rollback gives
/// the snapshot.
fn live_root_subvol() -> Result<tools::SubvolName, String> {
    let fstab = fs::read_to_string("/etc/fstab")
        .map_err(|e| format!("Cannot read /etc/fstab: {e}"))?;
    tools::root_subvol_name(&fstab)
}

/// Value of a variable in a GRUB environment block (grub-core/lib/envblk.c:
/// a "# GRUB Environment Block" header, name=value lines, '#' padding).
fn grubenv_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    content.lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| *name == key)
        .map(|(_, value)| value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{FsType, SubvolName};

    const STUB_FEDORA: &str = "\
search --no-floppy --root-dev-only --fs-uuid --set=dev 3f2a9c41-7d6e-4b85-a1c0-5e9d8b7f6a24
set prefix=($dev)/root/boot/grub2
export $prefix
configfile $prefix/grub.cfg
";

    const STUB_MIGRATED: &str = "\
set btrfs_relative_path=\"yes\"
search --no-floppy --root-dev-only --fs-uuid --set=dev 3f2a9c41-7d6e-4b85-a1c0-5e9d8b7f6a24
set prefix=($dev)/boot/grub2
export $prefix
configfile $prefix/grub.cfg
";

    fn top() -> PathBuf { PathBuf::from("/top") }

    fn default_is_root() -> Result<String, String> { Ok("root".into()) }

    fn default_unread() -> Result<String, String> {
        panic!("the default subvolume is read only when GRUB starts there")
    }

    fn select_from_stub(fstype: &FsType, stub: &str) -> Base {
        let stub = tools::parse_esp_stub(stub).unwrap();
        Base::select(fstype, stub.btrfs_relative, top(), default_is_root).unwrap()
    }

    // --- mode selection from the ESP stub ---

    #[test]
    fn fedora_stub_on_btrfs_resolves_from_top_level() {
        assert!(matches!(select_from_stub(&FsType::Btrfs, STUB_FEDORA),
            Base::BtrfsTopLevel { swap: None, .. }));
    }

    #[test]
    fn migrated_stub_on_btrfs_resolves_from_default_subvol() {
        assert!(matches!(select_from_stub(&FsType::Btrfs, STUB_MIGRATED),
            Base::BtrfsDefaultSubvol(_)));
    }

    #[test]
    fn btrfs_relative_path_one_selects_default_subvol() {
        let stub = STUB_FEDORA.replacen("search", "set btrfs_relative_path=1\nsearch", 1);
        assert!(matches!(select_from_stub(&FsType::Btrfs, &stub), Base::BtrfsDefaultSubvol(_)));
    }

    #[test]
    fn btrfs_relative_path_no_selects_top_level() {
        let stub = STUB_FEDORA.replacen("search", "set btrfs_relative_path=\"no\"\nsearch", 1);
        assert!(matches!(select_from_stub(&FsType::Btrfs, &stub), Base::BtrfsTopLevel { .. }));
    }

    #[test]
    fn btrfs_relative_path_is_ignored_off_btrfs() {
        // Fedora cloud images: the stub sets it but names the ext4 /boot.
        assert!(matches!(select_from_stub(&FsType::Ext4, STUB_MIGRATED), Base::FilesystemRoot(_)));
    }

    // --- resolution ---

    #[test]
    fn top_level_resolves_from_the_top_level_subvolume() {
        let base = Base::select(&FsType::Btrfs, false, top(), default_unread).unwrap();
        assert_eq!(base.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_resolves_inside_the_default_subvolume() {
        let base = Base::select(&FsType::Btrfs, true, top(), default_is_root).unwrap();
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/top/root/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_top_level_resolves_from_the_top_level() {
        let base = Base::select(&FsType::Btrfs, true, top(), || Ok(String::new())).unwrap();
        assert_eq!(base.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn filesystem_root_resolves_from_the_mount_point() {
        let base = Base::select(&FsType::Ext4, false, PathBuf::from("/boot"), default_unread).unwrap();
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_lookup_failure_is_an_error() {
        let base = Base::select(&FsType::Btrfs, true, top(), || Err("get-default failed".into()));
        assert!(base.is_err());
    }

    // --- snapshot before rollback ---

    fn swap_to(snapshot: &str) -> Base {
        Base::BtrfsTopLevel {
            toplevel: top(),
            swap: Some(PendingSwap {
                root: SubvolName::new("root".into()),
                snapshot: SubvolName::new(snapshot.into()),
            }),
        }
    }

    #[test]
    fn swap_maps_root_subvolume_paths_to_the_snapshot() {
        let base = swap_to("snap1");
        assert_eq!(base.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(base.resolve("/root"), Path::new("/top/snap1"));
        assert_eq!(base.resolve("//root/boot/grub2"), Path::new("/top/snap1/boot/grub2"));
    }

    #[test]
    fn swap_leaves_other_top_level_paths_alone() {
        let base = swap_to("snap1");
        assert_eq!(base.resolve("/home/user"), Path::new("/top/home/user"));
        assert_eq!(base.resolve("/rootfs/boot"), Path::new("/top/rootfs/boot"));
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
    }

    #[test]
    fn swap_accepts_slash_prefixed_fstab_name() {
        let base = Base::BtrfsTopLevel {
            toplevel: top(),
            swap: Some(PendingSwap {
                root: SubvolName::new("/root".into()),
                snapshot: SubvolName::new("2025-01-02_03-04-05".into()),
            }),
        };
        assert_eq!(base.resolve("/root/boot/vmlinuz-6.19.9"),
            Path::new("/top/2025-01-02_03-04-05/boot/vmlinuz-6.19.9"));
    }

    fn live_root_is_root() -> Result<SubvolName, String> { Ok(SubvolName::new("root".into())) }

    fn live_root_unread() -> Result<SubvolName, String> {
        panic!("the root subvolume's name matters only from the top level")
    }

    #[test]
    fn after_rollback_from_top_level_swaps_in_the_snapshot() {
        let base = Base::after_rollback(&FsType::Btrfs, false, top(), Path::new("/top/snap1"),
            live_root_is_root).unwrap();
        assert_eq!(base.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(base.resolve("/home/user"), Path::new("/top/home/user"));
    }

    #[test]
    fn after_rollback_refuses_snapshot_outside_the_top_level() {
        let base = Base::after_rollback(&FsType::Btrfs, false, top(), Path::new("/elsewhere/snap1"),
            live_root_is_root);
        assert!(base.is_err());
    }

    #[test]
    fn after_rollback_from_default_subvol_resolves_inside_the_snapshot() {
        let base = Base::after_rollback(&FsType::Btrfs, true, top(), Path::new("/top/snap1"),
            live_root_unread).unwrap();
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/top/snap1/vmlinuz-6.19.9"));
    }

    // /boot on its own filesystem is outside the snapshot: rollback leaves
    // it as it is, and GRUB reads it after the swap as before.
    #[test]
    fn after_rollback_off_btrfs_resolves_on_the_live_boot_filesystem() {
        let base = Base::after_rollback(&FsType::Ext4, false, PathBuf::from("/boot"),
            Path::new("/top/snap1"), live_root_unread).unwrap();
        assert_eq!(base.resolve("/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
        assert_eq!(base.resolve("/grub2/grub.cfg"), Path::new("/boot/grub2/grub.cfg"));
    }

    // --- subvolume overrides in the stub ---

    fn read_stub(name: &str, content: &str) -> Result<tools::EspStub, GrubContextError> {
        let path = std::env::temp_dir().join(format!("atomic-rollback-test-stub-{name}.cfg"));
        fs::write(&path, content).unwrap();
        let stub = read_esp_stub(&path);
        fs::remove_file(&path).unwrap();
        stub
    }

    fn refused_naming(stub: Result<tools::EspStub, GrubContextError>, variable: &str) -> bool {
        matches!(stub, Err(GrubContextError::Other(msg)) if msg.contains(&format!("sets {variable},")))
    }

    #[test]
    fn stub_setting_btrfs_subvol_is_refused() {
        let stub = STUB_MIGRATED.replacen("search", "set btrfs_subvol=\"@/.snapshots/1/snapshot\"\nsearch", 1);
        assert!(refused_naming(read_stub("subvol", &stub), "btrfs_subvol"));
    }

    #[test]
    fn stub_setting_btrfs_subvolid_is_refused() {
        let stub = STUB_FEDORA.replacen("search", "btrfs_subvolid=256\nsearch", 1);
        assert!(refused_naming(read_stub("subvolid", &stub), "btrfs_subvolid"));
    }

    #[test]
    fn stubs_fedora_and_migrate_write_are_read() {
        assert!(read_stub("fedora", STUB_FEDORA).is_ok());
        assert!(read_stub("migrated", STUB_MIGRATED).is_ok());
    }

    // --- grubenv ---

    #[test]
    fn grubenv_value_reads_a_variable() {
        let env = format!(
            "# GRUB Environment Block\nboot_success=1\nblsdir=/root/boot/loader/entries\nsaved_entry=x\n{}",
            "#".repeat(64));
        assert_eq!(grubenv_value(&env, "blsdir"), Some("/root/boot/loader/entries"));
        assert_eq!(grubenv_value(&env, "saved_entry"), Some("x"));
    }

    #[test]
    fn grubenv_value_absent_variable() {
        let env = format!("# GRUB Environment Block\nboot_success=1\n{}", "#".repeat(64));
        assert_eq!(grubenv_value(&env, "blsdir"), None);
        assert_eq!(grubenv_value(&env, "boot"), None);
    }
}
