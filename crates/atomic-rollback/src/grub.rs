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

/// Errors from building a GrubContext. Each access only root has is its
/// own cause, so the caller can tell "run as root" apart from a real
/// boot-chain problem and name the access that was missing.
pub enum GrubContextError {
    /// Reading the ESP grub.cfg was refused (EACCES); Fedora makes it
    /// readable only by root.
    EspUnreadable { path: PathBuf },
    /// Mounting the Btrfs top-level subvolume needs root (mount(2), EPERM).
    MountNotPermitted,
    Other(String),
}

impl From<String> for GrubContextError {
    fn from(s: String) -> Self { GrubContextError::Other(s) }
}

/// Why GRUB's lookup of a path fails.
#[derive(Debug, PartialEq)]
pub enum LookupFailure {
    /// GRUB reports file `PATH' not found.
    FileNotFound,
}

impl LookupFailure {
    /// The failure for grub_path, in GRUB's words.
    fn message(&self, grub_path: &str) -> String {
        match self {
            LookupFailure::FileNotFound => format!("file `{grub_path}' not found"),
        }
    }
}

/// A failed lookup, named by the GRUB path and where GRUB starts it, never
/// by a Linux path: a mount check made may be gone when the user reads the
/// report.
#[derive(Debug)]
pub struct LookupError {
    pub grub_path: String,
    pub failure: LookupFailure,
    starting_lookup_dir: &'static str,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}; GRUB starts the lookup at {}", self.failure.message(&self.grub_path), self.starting_lookup_dir)
    }
}

/// The directory blscfg reads boot entries from.
pub struct BlsDir {
    /// The directory as GRUB names it.
    pub grub_path: String,
    /// The Linux path where it is visible.
    pub linux: PathBuf,
}

impl BlsDir {
    /// The GRUB path of the entry named file, as blscfg opens it.
    pub fn entry(&self, file: &str) -> String {
        format!("{}/{file}", self.grub_path.trim_end_matches('/'))
    }
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

/// The text of the ESP stub, the grub.cfg GRUB runs first.
fn read_esp_stub(path: &Path) -> Result<String, GrubContextError> {
    fs::read_to_string(path).map_err(|e| match e.kind() {
        io::ErrorKind::PermissionDenied => GrubContextError::EspUnreadable { path: path.to_path_buf() },
        _ => GrubContextError::Other(format!("cannot read ESP grub.cfg: {e}")),
    })
}

/// The stub's contract values, with the block device holding the
/// filesystem it names and that filesystem's type. Refuses a stub whose
/// resolution check does not model.
fn boot_filesystem(content: &str) -> Result<(tools::EspStub, tools::DevicePath, tools::FsType), String> {
    let stub = tools::parse_esp_stub(content)?;
    let (device, fstype) = boot_device(&stub)?;
    reject_btrfs_subvol_variables(content, &stub, &fstype)?;
    Ok((stub, device, fstype))
}

/// Variables that point GRUB's Btrfs driver at a named subvolume
/// (Fedora's grub2 2.12 patches, grub-core/fs/btrfs.c,
/// btrfs_handle_subvol). Neither Fedora's gen_grub_cfgstub nor migrate
/// writes them.
const BTRFS_SUBVOL_VARIABLES: [&str; 2] = ["btrfs_subvol", "btrfs_subvolid"];

/// Refuses a stub that sets btrfs_subvol or btrfs_subvolid where GRUB reads
/// them: on Btrfs, with btrfs_relative_path set, before configfile hands
/// over (Fedora's grub2 2.12 patches, grub-core/fs/btrfs.c,
/// grub_btrfs_mount and find_path). check does not model where GRUB
/// resolves paths under either.
fn reject_btrfs_subvol_variables(content: &str, stub: &tools::EspStub, fstype: &tools::FsType) -> Result<(), String> {
    if *fstype != tools::FsType::Btrfs || !stub.btrfs_relative {
        return Ok(());
    }
    match BTRFS_SUBVOL_VARIABLES.into_iter()
        .find(|name| tools::before_configfile(content).any(|line| tools::grub_assignment(line, name).is_some()))
    {
        Some(name) => Err(format!(
            "ESP grub.cfg sets {name}, which neither Fedora nor atomic-rollback writes, \
             with btrfs_relative_path. check cannot tell which subvolume GRUB resolves paths from")),
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
        let content = read_esp_stub(&root.join(&P.esp_dir[1..]).join("grub.cfg"))?;
        let (stub, device, fstype) = boot_filesystem(&content)?;

        let mount = if fstype == tools::FsType::Btrfs {
            if !tools::is_root() {
                return Err(GrubContextError::MountNotPermitted);
            }
            tools::mount_toplevel_ro(&device)?
        } else {
            tools::get_mount_point(&device.into_device_spec())?
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
        let content = read_esp_stub(&Path::new(P.esp_dir).join("grub.cfg"))?;
        let (stub, device, fstype) = boot_filesystem(&content)?;

        let mount = if fstype == tools::FsType::Btrfs {
            None
        } else {
            Some(tools::get_mount_point(&device.into_device_spec())?)
        };
        let fs_root = mount.as_ref().map_or_else(|| toplevel.to_path_buf(), |m| PathBuf::from(m.path()));

        let starting_lookup_dir = StartingLookupDir::after_rollback(&fstype, stub.btrfs_relative, fs_root, exchange);

        Ok(Self { starting_lookup_dir, grub_dir: stub.grub_dir, _mount: mount })
    }

    /// GRUB path of a file in the stub's GRUB directory.
    pub fn grub_dir_file(&self, file: &str) -> String {
        format!("{}/{file}", self.grub_dir.trim_end_matches('/'))
    }

    /// The Linux path of the file GRUB opens at grub_path.
    pub fn find_file(&self, grub_path: &str) -> Result<PathBuf, LookupError> {
        let linux_path = self.starting_lookup_dir.resolve(grub_path);
        if linux_path.exists() {
            Ok(linux_path)
        } else {
            Err(self.lookup_error(grub_path, LookupFailure::FileNotFound))
        }
    }

    /// The Linux path of the directory GRUB lists at grub_path.
    fn find_dir(&self, grub_path: &str) -> Result<PathBuf, LookupError> {
        let linux_path = self.starting_lookup_dir.resolve(grub_path);
        if fs::read_dir(&linux_path).is_ok() {
            Ok(linux_path)
        } else {
            Err(self.lookup_error(grub_path, LookupFailure::FileNotFound))
        }
    }

    fn lookup_error(&self, grub_path: &str, failure: LookupFailure) -> LookupError {
        LookupError {
            grub_path: grub_path.to_string(),
            failure,
            starting_lookup_dir: self.starting_lookup_dir.describe(),
        }
    }

    /// The Linux path of the directory blscfg reads boot entries from.
    /// blscfg scans the blsdir variable, which grub.cfg loads from
    /// $prefix/grubenv (util/grub.d/00_header.in), or BLS_CONFIG_PATH when
    /// it is unset, then BOOT_BLS_CONFIG_PATH if listing that fails.
    pub fn blsdir(&self) -> Result<BlsDir, String> {
        // A grubenv GRUB cannot read loads nothing, as when it is absent.
        let grubenv = self.find_file(&self.grub_dir_file("grubenv")).ok()
            .and_then(|path| fs::read_to_string(path).ok());
        let blsdir = grubenv.as_deref()
            .and_then(|env| grubenv_value(env, "blsdir"))
            .unwrap_or(BLS_CONFIG_PATH);

        let mut tried = Vec::new();
        for dir in [blsdir, BOOT_BLS_CONFIG_PATH] {
            match self.find_dir(dir) {
                Ok(linux) => return Ok(BlsDir { grub_path: dir.to_string(), linux }),
                Err(e) => tried.push(e.failure.message(dir)),
            }
        }
        Err(format!("GRUB finds no boot entry directory: {}; GRUB starts the lookup at {}",
            tried.join(", then "), self.starting_lookup_dir.describe()))
    }
}

/// The block device holding the filesystem the stub's search --fs-uuid
/// names, and that filesystem's type. GRUB's resolution depends on the
/// type, so an unknown type is an error, not a guess.
fn boot_device(stub: &tools::EspStub) -> Result<(tools::DevicePath, tools::FsType), String> {
    let unknown = |e| format!("cannot determine the filesystem type of UUID={}: {e}", stub.boot_uuid.as_str());
    let device = tools::blkid_device_for_uuid(&stub.boot_uuid).map_err(unknown)?;
    let fstype = tools::blkid_fstype(&device).map_err(unknown)?;
    Ok((device, fstype))
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
    fn exchange_maps_snapshot_paths_to_the_old_root() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(starting_lookup_dir.resolve("/snap1/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
        assert_eq!(starting_lookup_dir.resolve("/snap1"), Path::new("/top/root"));
    }

    #[test]
    fn exchange_leaves_other_top_level_paths_alone() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(starting_lookup_dir.resolve("/home/user"), Path::new("/top/home/user"));
        assert_eq!(starting_lookup_dir.resolve("/rootfs/boot"), Path::new("/top/rootfs/boot"));
        assert_eq!(starting_lookup_dir.resolve("/snap10/boot"), Path::new("/top/snap10/boot"));
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

    /// check's verdict on the stub content, on a boot filesystem of type
    /// fstype.
    fn btrfs_subvol_verdict(content: &str, fstype: FsType) -> Result<(), String> {
        reject_btrfs_subvol_variables(content, &tools::parse_esp_stub(content).unwrap(), &fstype)
    }

    fn refused_naming(verdict: Result<(), String>, variable: &str) -> bool {
        verdict.is_err_and(|msg| msg.contains(&format!("sets {variable},")))
    }

    const BTRFS_SUBVOL: &str = "set btrfs_subvol=\"@/.snapshots/1/snapshot\"\n";
    const BTRFS_SUBVOLID: &str = "btrfs_subvolid=256\n";

    #[test]
    fn btrfs_subvol_with_btrfs_relative_path_is_refused() {
        let stub = format!("{BTRFS_SUBVOL}{STUB_MIGRATED}");
        assert!(refused_naming(btrfs_subvol_verdict(&stub, FsType::Btrfs), "btrfs_subvol"));
    }

    #[test]
    fn btrfs_subvolid_with_btrfs_relative_path_is_refused() {
        let stub = format!("{BTRFS_SUBVOLID}{STUB_MIGRATED}");
        assert!(refused_naming(btrfs_subvol_verdict(&stub, FsType::Btrfs), "btrfs_subvolid"));
    }

    // GRUB's Btrfs driver reads btrfs_subvol and btrfs_subvolid only when
    // btrfs_relative_path is set (Fedora's grub2 2.12 patches,
    // grub-core/fs/btrfs.c, grub_btrfs_mount and find_path).
    #[test]
    fn btrfs_subvol_variables_without_btrfs_relative_path_are_ignored() {
        let stub = format!("{BTRFS_SUBVOL}{BTRFS_SUBVOLID}{STUB_FEDORA}");
        assert_eq!(btrfs_subvol_verdict(&stub, FsType::Btrfs), Ok(()));
    }

    #[test]
    fn btrfs_subvol_variables_off_btrfs_are_ignored() {
        let stub = format!("{BTRFS_SUBVOL}{BTRFS_SUBVOLID}{STUB_MIGRATED}");
        assert_eq!(btrfs_subvol_verdict(&stub, FsType::Ext4), Ok(()));
    }

    #[test]
    fn btrfs_subvol_variables_after_configfile_are_ignored() {
        let stub = format!("{STUB_MIGRATED}{BTRFS_SUBVOL}{BTRFS_SUBVOLID}");
        assert_eq!(btrfs_subvol_verdict(&stub, FsType::Btrfs), Ok(()));
    }

    #[test]
    fn stubs_fedora_and_migrate_write_are_accepted() {
        assert_eq!(btrfs_subvol_verdict(STUB_FEDORA, FsType::Btrfs), Ok(()));
        assert_eq!(btrfs_subvol_verdict(STUB_MIGRATED, FsType::Btrfs), Ok(()));
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
