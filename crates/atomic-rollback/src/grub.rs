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

use crate::platform::FEDORA as P;
use crate::swap::RenameExchange;
use crate::tools;

/// BLS directory blscfg scans when the blsdir variable is unset
/// (grub-core/commands/blscfg.c, GRUB_BLS_CONFIG_PATH).
const BLS_CONFIG_PATH: &str = "/loader/entries";

/// Directory blscfg scans when listing the first one fails, if blscfg was
/// called without an argument, as Fedora's grub.cfg calls it
/// (grub-core/commands/blscfg.c, find_entry).
const BOOT_BLS_CONFIG_PATH: &str = "/boot/loader/entries";

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

/// Where GRUB starts resolving an absolute path, and the Linux directory
/// where that starting point is visible.
pub enum StartingLookupDir {
    /// Not Btrfs: the filesystem's root, at this mount point.
    FilesystemRoot(PathBuf),
    /// Btrfs, btrfs_relative_path not set: the top-level subvolume,
    /// mounted here. exchange is set when checking a snapshot before
    /// rollback.
    BtrfsTopLevel { toplevel: PathBuf, exchange: Option<RenameExchange> },
    /// Btrfs, btrfs_relative_path set: the default subvolume, whose
    /// directory is this.
    BtrfsDefaultSubvol(PathBuf),
}

impl StartingLookupDir {
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
            tools::FsType::Btrfs if btrfs_relative => Self::BtrfsDefaultSubvol(fs_root.join(default_subvol()?)),
            tools::FsType::Btrfs => Self::BtrfsTopLevel { toplevel: fs_root, exchange: None },
            _ => Self::FilesystemRoot(fs_root),
        })
    }

    /// Selects GRUB's starting point as it will be once rollback has made
    /// the exchange. fs_root is where the root of the filesystem the ESP
    /// stub names is mounted; on Btrfs that is the top-level subvolume, in
    /// which the exchange renames the root subvolume and the snapshot.
    pub fn after_rollback(
        fstype: &tools::FsType,
        btrfs_relative: bool,
        fs_root: PathBuf,
        exchange: &RenameExchange,
    ) -> Self {
        match fstype {
            // After the exchange, rollback sets the subvolume then named as
            // the root subvolume, which is the snapshot, as the default.
            tools::FsType::Btrfs if btrfs_relative =>
                Self::BtrfsDefaultSubvol(fs_root.join(exchange.before_exchange(exchange.root.as_str()))),
            tools::FsType::Btrfs => Self::BtrfsTopLevel { toplevel: fs_root, exchange: Some(exchange.clone()) },
            // A separate boot filesystem is outside the snapshot, and
            // rollback leaves it as it is.
            _ => Self::FilesystemRoot(fs_root),
        }
    }

    /// Names the starting point for check's output.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::FilesystemRoot(_) => "the root of the boot filesystem (not Btrfs)",
            Self::BtrfsTopLevel { .. } => "the Btrfs top-level subvolume (btrfs_relative_path not set)",
            Self::BtrfsDefaultSubvol(_) => "the Btrfs default subvolume (btrfs_relative_path set)",
        }
    }

    /// Translates a GRUB path into the Linux path of the file GRUB reads.
    /// GRUB skips leading slashes and walks the rest from its starting point.
    pub fn resolve(&self, grub_path: &str) -> PathBuf {
        let path = grub_path.trim_start_matches('/');
        match self {
            Self::FilesystemRoot(dir) | Self::BtrfsDefaultSubvol(dir) => dir.join(path),
            Self::BtrfsTopLevel { toplevel, exchange: None } => toplevel.join(path),
            Self::BtrfsTopLevel { toplevel, exchange: Some(exchange) } => toplevel.join(exchange.before_exchange(path)),
        }
    }
}

/// Captures how GRUB resolves paths on the filesystem the ESP stub names.
/// Used by check.rs to verify that GRUB can find its configuration, its
/// boot entries, and the kernels they name.
pub struct GrubContext {
    pub starting_lookup_dir: StartingLookupDir,
    /// The GRUB directory the ESP stub sets $prefix to (gen_grub_cfgstub's
    /// GRUB_DIR). GRUB loads grub.cfg and grubenv from it.
    grub_dir: String,
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
    reject_btrfs_subvol_variables(&content)?;
    Ok(tools::parse_esp_stub(&content)?)
}

/// Variables that point GRUB's Btrfs driver at a named subvolume
/// (grub-core/fs/btrfs.c, btrfs_handle_subvol). Neither Fedora's
/// gen_grub_cfgstub nor migrate writes them.
const BTRFS_SUBVOL_VARIABLES: [&str; 2] = ["btrfs_subvol", "btrfs_subvolid"];

/// Refuses a stub that sets btrfs_subvol or btrfs_subvolid: check does not
/// model where GRUB resolves paths under either.
fn reject_btrfs_subvol_variables(content: &str) -> Result<(), String> {
    match BTRFS_SUBVOL_VARIABLES.into_iter()
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
    pub fn new(starting_lookup_dir: StartingLookupDir, grub_dir: String) -> Self {
        Self { starting_lookup_dir, grub_dir, _mount: None }
    }

    /// Builds a context from the live system's ESP grub.cfg. On Btrfs,
    /// mounts the top-level subvolume read-only for the context's lifetime;
    /// otherwise uses the filesystem's mount point, mounting it at a
    /// temporary mount point if needed.
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

        let starting_lookup_dir = StartingLookupDir::select(&fstype, stub.btrfs_relative, PathBuf::from(mount.path()),
            || tools::btrfs_subvol_get_default(mount.path()).map(|d| d.path().to_string()))?;

        Ok(Self { starting_lookup_dir, grub_dir: stub.grub_dir, _mount: Some(mount) })
    }

    /// Builds a context for verifying a snapshot before rollback makes the
    /// exchange. Reads the ESP config from the live system (the ESP is vfat,
    /// not in the snapshot). toplevel is where rollback mounted the Btrfs
    /// top-level subvolume. A boot filesystem other than Btrfs is outside
    /// the snapshot, so its live mount point is used, mounting it at a
    /// temporary mount point if needed.
    pub fn for_snapshot(toplevel: &Path, exchange: &RenameExchange) -> Result<Self, GrubContextError> {
        let stub = read_esp_stub(&Path::new(P.esp_dir).join("grub.cfg"))?;
        let fstype = boot_fstype(&stub)?;

        let mount = if fstype == tools::FsType::Btrfs {
            None
        } else {
            Some(tools::get_mount_point(&stub.boot_uuid.clone().into_device_spec())?)
        };
        let fs_root = mount.as_ref().map_or_else(|| toplevel.to_path_buf(), |m| PathBuf::from(m.path()));

        let starting_lookup_dir = StartingLookupDir::after_rollback(&fstype, stub.btrfs_relative, fs_root, exchange);

        Ok(Self { starting_lookup_dir, grub_dir: stub.grub_dir, _mount: mount })
    }

    pub fn resolve(&self, grub_path: &str) -> PathBuf {
        self.starting_lookup_dir.resolve(grub_path)
    }

    /// GRUB path of a file in the stub's GRUB directory.
    pub fn grub_dir_file(&self, file: &str) -> String {
        format!("{}/{file}", self.grub_dir.trim_end_matches('/'))
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
    /// $prefix/grubenv (util/grub.d/00_header.in), or BLS_CONFIG_PATH when
    /// it is unset, then BOOT_BLS_CONFIG_PATH if listing that fails.
    pub fn blsdir(&self) -> Result<PathBuf, String> {
        // A grubenv GRUB cannot read loads nothing, as when it is absent.
        let grubenv = fs::read_to_string(self.resolve(&self.grub_dir_file("grubenv"))).ok();
        let blsdir = grubenv.as_deref()
            .and_then(|env| grubenv_value(env, "blsdir"))
            .unwrap_or(BLS_CONFIG_PATH);

        let mut tried = Vec::new();
        for dir in [blsdir, BOOT_BLS_CONFIG_PATH] {
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

    fn select_from_stub(fstype: &FsType, stub: &str) -> StartingLookupDir {
        let stub = tools::parse_esp_stub(stub).unwrap();
        StartingLookupDir::select(fstype, stub.btrfs_relative, top(), default_is_root).unwrap()
    }

    // --- starting lookup directory from the ESP stub ---

    #[test]
    fn fedora_stub_on_btrfs_resolves_from_top_level() {
        assert!(matches!(select_from_stub(&FsType::Btrfs, STUB_FEDORA),
            StartingLookupDir::BtrfsTopLevel { exchange: None, .. }));
    }

    #[test]
    fn migrated_stub_on_btrfs_resolves_from_default_subvol() {
        assert!(matches!(select_from_stub(&FsType::Btrfs, STUB_MIGRATED),
            StartingLookupDir::BtrfsDefaultSubvol(_)));
    }

    #[test]
    fn btrfs_relative_path_one_selects_default_subvol() {
        let stub = STUB_FEDORA.replacen("search", "set btrfs_relative_path=1\nsearch", 1);
        assert!(matches!(select_from_stub(&FsType::Btrfs, &stub), StartingLookupDir::BtrfsDefaultSubvol(_)));
    }

    #[test]
    fn btrfs_relative_path_no_selects_top_level() {
        let stub = STUB_FEDORA.replacen("search", "set btrfs_relative_path=\"no\"\nsearch", 1);
        assert!(matches!(select_from_stub(&FsType::Btrfs, &stub), StartingLookupDir::BtrfsTopLevel { .. }));
    }

    #[test]
    fn btrfs_relative_path_is_ignored_off_btrfs() {
        // Fedora cloud images: the stub sets it but names the ext4 /boot.
        assert!(matches!(select_from_stub(&FsType::Ext4, STUB_MIGRATED), StartingLookupDir::FilesystemRoot(_)));
    }

    // --- resolution ---

    #[test]
    fn top_level_resolves_from_the_top_level_subvolume() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, false, top(), default_unread).unwrap();
        assert_eq!(starting_lookup_dir.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_resolves_inside_the_default_subvolume() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, true, top(), default_is_root).unwrap();
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/top/root/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_top_level_resolves_from_the_top_level() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, true, top(), || Ok(String::new())).unwrap();
        assert_eq!(starting_lookup_dir.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn filesystem_root_resolves_from_the_mount_point() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Ext4, false, PathBuf::from("/boot"), default_unread).unwrap();
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_lookup_failure_is_an_error() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, true, top(), || Err("get-default failed".into()));
        assert!(starting_lookup_dir.is_err());
    }

    // --- snapshot before rollback ---

    fn exchange_of_root_and(snapshot: &str) -> RenameExchange {
        RenameExchange { root: SubvolName::new("root".into()), snapshot: SubvolName::new(snapshot.into()) }
    }

    fn exchange_to(snapshot: &str) -> StartingLookupDir {
        StartingLookupDir::BtrfsTopLevel { toplevel: top(), exchange: Some(exchange_of_root_and(snapshot)) }
    }

    #[test]
    fn exchange_maps_root_subvolume_paths_to_the_snapshot() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(starting_lookup_dir.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(starting_lookup_dir.resolve("/root"), Path::new("/top/snap1"));
        assert_eq!(starting_lookup_dir.resolve("//root/boot/grub2"), Path::new("/top/snap1/boot/grub2"));
    }

    #[test]
    fn exchange_leaves_other_top_level_paths_alone() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(starting_lookup_dir.resolve("/home/user"), Path::new("/top/home/user"));
        assert_eq!(starting_lookup_dir.resolve("/rootfs/boot"), Path::new("/top/rootfs/boot"));
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
    }

    #[test]
    fn exchange_accepts_slash_prefixed_fstab_name() {
        let starting_lookup_dir = StartingLookupDir::BtrfsTopLevel {
            toplevel: top(),
            exchange: Some(RenameExchange {
                root: SubvolName::new("/root".into()),
                snapshot: SubvolName::new("2025-01-02_03-04-05".into()),
            }),
        };
        assert_eq!(starting_lookup_dir.resolve("/root/boot/vmlinuz-6.19.9"),
            Path::new("/top/2025-01-02_03-04-05/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn after_rollback_from_top_level_exchanges_in_the_snapshot() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Btrfs, false, top(),
            &exchange_of_root_and("snap1"));
        assert_eq!(starting_lookup_dir.resolve("/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(starting_lookup_dir.resolve("/home/user"), Path::new("/top/home/user"));
    }

    #[test]
    fn after_rollback_from_default_subvol_resolves_inside_the_snapshot() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Btrfs, true, top(),
            &exchange_of_root_and("snap1"));
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/top/snap1/vmlinuz-6.19.9"));
    }

    // /boot on its own filesystem is outside the snapshot: rollback leaves
    // it as it is, and GRUB reads it after the exchange as before.
    #[test]
    fn after_rollback_off_btrfs_resolves_on_the_live_boot_filesystem() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Ext4, false, PathBuf::from("/boot"),
            &exchange_of_root_and("snap1"));
        assert_eq!(starting_lookup_dir.resolve("/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
        assert_eq!(starting_lookup_dir.resolve("/grub2/grub.cfg"), Path::new("/boot/grub2/grub.cfg"));
    }

    // --- btrfs_subvol variables in the stub ---

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
