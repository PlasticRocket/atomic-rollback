//! GRUB path resolution. check verifies the boot chain as GRUB walks it:
//! the ESP stub names a filesystem and a prefix, grub.cfg and grubenv sit
//! under the prefix, grubenv's blsdir names the BLS directory, and each
//! BLS entry names a kernel and initramfs. This module looks those GRUB
//! paths up as GRUB's filesystem code does and finds the Linux paths where
//! the same files are visible.
//!
//! On Btrfs, GRUB's driver resolves an absolute path from the top-level
//! subvolume (ID 5) unless btrfs_relative_path is set, and from the
//! default subvolume when it is (Fedora's grub2 2.12 patches,
//! grub-core/fs/btrfs.c, find_path). Neither is necessarily the subvolume
//! Linux mounts at /.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::platform::FEDORA as P;
use crate::swap::{join_below, RenameExchange};
use crate::tools;

/// BLS directory blscfg scans when the blsdir variable is unset
/// (Fedora's grub2 2.12 patches, grub-core/commands/blscfg.c,
/// GRUB_BLS_CONFIG_PATH).
const BLS_CONFIG_PATH: &str = "/loader/entries/";

/// Directory blscfg scans when listing the first one fails, if blscfg was
/// called without an argument, as Fedora's grub.cfg calls it (Fedora's
/// grub2 2.12 patches, grub-core/commands/blscfg.c, find_entry).
const BOOT_BLS_CONFIG_PATH: &str = "/boot/loader/entries/";

/// The symbolic link at which a lookup fails on Btrfs: find_path's
/// symlinks_max starts at 32 and the lookup fails when it reaches 0
/// (grub-core/fs/btrfs.c, find_path).
const BTRFS_SYMLINK_LIMIT: u32 = 32;

/// The symbolic link at which a lookup fails on other filesystems: the
/// lookup fails when symlinknest reaches 8 (grub-core/fs/fshelp.c,
/// find_file).
const FSHELP_SYMLINK_LIMIT: u32 = 8;

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

/// Why GRUB's lookup of a path fails, each with GRUB's message for it
/// (grub-core/fs/btrfs.c, find_path, grub_btrfs_open and grub_btrfs_dir;
/// grub-core/fs/fshelp.c, find_file and grub_fshelp_find_file_real).
#[derive(Debug, PartialEq)]
pub enum LookupFailure {
    /// A component is missing: file `PATH' not found.
    FileNotFound,
    /// A component GRUB walks through is not a directory, or a directory
    /// was expected.
    NotADirectory,
    /// The file GRUB opens is not a regular file.
    NotARegularFile,
    /// The lookup met more symbolic links than GRUB follows.
    SymlinkLoop,
}

impl LookupFailure {
    /// The failure for grub_path, in GRUB's words.
    fn message(&self, grub_path: &str) -> String {
        match self {
            LookupFailure::FileNotFound => format!("file `{grub_path}' not found"),
            LookupFailure::NotADirectory => format!("'{grub_path}': not a directory"),
            LookupFailure::NotARegularFile => format!("'{grub_path}': not a regular file"),
            LookupFailure::SymlinkLoop => format!("'{grub_path}': too deep nesting of symlinks"),
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

/// What a lookup reaches, as GRUB tells it apart.
#[derive(Debug, Clone, Copy, PartialEq)]
enum NodeKind {
    Directory,
    RegularFile,
    /// A device, FIFO or socket: GRUB's Btrfs driver reaches it but cannot
    /// open or list it, and fshelp does not see it.
    Other,
}

impl NodeKind {
    fn of(meta: &fs::Metadata) -> Self {
        let file_type = meta.file_type();
        if file_type.is_dir() {
            NodeKind::Directory
        } else if file_type.is_file() {
            NodeKind::RegularFile
        } else {
            NodeKind::Other
        }
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
                Self::BtrfsDefaultSubvol(fs_root.join(exchange.before_exchange(Path::new(exchange.root.as_str())))),
            tools::FsType::Btrfs => Self::BtrfsTopLevel { toplevel: fs_root, exchange: Some(exchange.clone()) },
            // A separate boot filesystem is outside the snapshot, and
            // rollback leaves it as it is.
            _ => Self::FilesystemRoot(fs_root),
        }
    }

    /// The symbolic link at which GRUB's lookup fails.
    fn symlink_limit(&self) -> u32 {
        match self {
            Self::FilesystemRoot(_) => FSHELP_SYMLINK_LIMIT,
            Self::BtrfsTopLevel { .. } | Self::BtrfsDefaultSubvol(_) => BTRFS_SYMLINK_LIMIT,
        }
    }

    /// The Linux path where the entry at below is visible. below is a path
    /// below the starting lookup directory, as GRUB walks it, with no
    /// symbolic link or dot component in it.
    fn linux_path(&self, below: &Path) -> PathBuf {
        match self {
            Self::FilesystemRoot(dir) | Self::BtrfsDefaultSubvol(dir) => join_below(dir, below),
            Self::BtrfsTopLevel { toplevel, exchange: None } => join_below(toplevel, below),
            Self::BtrfsTopLevel { toplevel, exchange: Some(exchange) } =>
                join_below(toplevel, &exchange.before_exchange(below)),
        }
    }

    /// Looks grub_path up as GRUB's filesystem code walks it, and returns
    /// the Linux path of what the lookup reaches, with its kind. On Btrfs
    /// that is find_path (grub-core/fs/btrfs.c); elsewhere it is fshelp's
    /// find_file (grub-core/fs/fshelp.c), which the ext2 and xfs drivers
    /// use. Each component is looked up in the Linux directory where GRUB's
    /// current directory is visible, and a symbolic link is never followed
    /// in the running system's namespace: it is read and followed as GRUB
    /// follows it, an absolute target from the starting lookup directory
    /// and a relative one from the link's directory. is_subvolume_root
    /// tells whether a Linux directory is the root of a Btrfs subvolume,
    /// which on Btrfs is its own parent.
    fn lookup(&self, grub_path: &str, is_subvolume_root: impl Fn(&Path) -> bool)
        -> Result<(PathBuf, NodeKind), LookupFailure>
    {
        let btrfs = !matches!(self, Self::FilesystemRoot(_));
        let mut below = PathBuf::new();
        let mut kind = NodeKind::Directory;
        let mut remaining = grub_path.as_bytes().to_vec();
        let mut links = 0;
        loop {
            let start = remaining.iter().position(|&b| b != b'/').unwrap_or(remaining.len());
            let end = remaining[start..].iter().position(|&b| b == b'/').map_or(remaining.len(), |i| start + i);
            if start == end {
                break;
            }
            if kind != NodeKind::Directory {
                return Err(LookupFailure::NotADirectory);
            }
            let name = OsStr::from_bytes(&remaining[start..end]).to_os_string();
            let rest = remaining.split_off(end);

            if name == ".." {
                // fshelp goes back up the path it walked, stopping at the
                // root (fshelp.c, go_up_a_level). Btrfs reads the
                // directory's parent from its inode ref, and a subvolume's
                // root directory is its own parent (btrfs.c, find_path).
                if !(btrfs && is_subvolume_root(&self.linux_path(&below))) {
                    below.pop();
                }
            } else if name != "." {
                let next = below.join(&name);
                let linux_path = self.linux_path(&next);
                let meta = fs::symlink_metadata(&linux_path).map_err(|_| LookupFailure::FileNotFound)?;
                if meta.file_type().is_symlink() {
                    links += 1;
                    if links == self.symlink_limit() {
                        return Err(LookupFailure::SymlinkLoop);
                    }
                    let target = fs::read_link(&linux_path).map_err(|_| LookupFailure::FileNotFound)?;
                    let target = target.into_os_string().into_vec();
                    if target.first() == Some(&b'/') {
                        below = PathBuf::new();
                    }
                    remaining = [target, rest].concat();
                    continue;
                }
                kind = NodeKind::of(&meta);
                // fshelp does not see a node of another kind (fshelp.c,
                // find_file_iter); Btrfs refuses a regular file followed by
                // a slash (btrfs.c, find_path).
                if (!btrfs && kind == NodeKind::Other) || (btrfs && kind == NodeKind::RegularFile && !rest.is_empty()) {
                    return Err(LookupFailure::FileNotFound);
                }
                below = next;
            }
            remaining = rest;
        }
        Ok((self.linux_path(&below), kind))
    }

    /// Names the starting point for check's output.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::FilesystemRoot(_) => "the root of the boot filesystem (not Btrfs)",
            Self::BtrfsTopLevel { .. } => "the Btrfs top-level subvolume (btrfs_relative_path not set)",
            Self::BtrfsDefaultSubvol(_) => "the Btrfs default subvolume (btrfs_relative_path set)",
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

    /// The Linux path of the regular file GRUB opens at grub_path.
    pub fn find_file(&self, grub_path: &str) -> Result<PathBuf, LookupError> {
        self.find(grub_path, NodeKind::RegularFile, LookupFailure::NotARegularFile)
    }

    /// The Linux path of the directory GRUB lists at grub_path.
    fn find_dir(&self, grub_path: &str) -> Result<PathBuf, LookupError> {
        self.find(grub_path, NodeKind::Directory, LookupFailure::NotADirectory)
    }

    /// Looks grub_path up and requires it to reach a node of kind
    /// expected, failing with otherwise when it reaches another.
    fn find(&self, grub_path: &str, expected: NodeKind, otherwise: LookupFailure) -> Result<PathBuf, LookupError> {
        let failure = match self.starting_lookup_dir.lookup(grub_path, tools::is_btrfs_subvolume_root) {
            Ok((linux_path, kind)) if kind == expected => return Ok(linux_path),
            Ok(_) => otherwise,
            Err(failure) => failure,
        };
        Err(LookupError {
            grub_path: grub_path.to_string(),
            failure,
            starting_lookup_dir: self.starting_lookup_dir.describe(),
        })
    }

    /// The directory blscfg reads boot entries from. blscfg (Fedora's grub2
    /// 2.12 patches, grub-core/commands/blscfg.c, find_entry) lists the
    /// blsdir variable, which grub.cfg loads from $prefix/grubenv
    /// (util/grub.d/00_header.in), or BLS_CONFIG_PATH when it is unset, then
    /// BOOT_BLS_CONFIG_PATH if listing that fails.
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

    /// The Linux path GRUB reaches for a path with no link or dot in it.
    fn resolve(starting_lookup_dir: &StartingLookupDir, grub_path: &str) -> PathBuf {
        starting_lookup_dir.linux_path(Path::new(grub_path.trim_start_matches('/')))
    }

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
        assert_eq!(resolve(&starting_lookup_dir, "/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_resolves_inside_the_default_subvolume() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, true, top(), default_is_root).unwrap();
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/top/root/vmlinuz-6.19.9"));
    }

    #[test]
    fn default_subvol_top_level_resolves_from_the_top_level() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Btrfs, true, top(), || Ok(String::new())).unwrap();
        assert_eq!(resolve(&starting_lookup_dir, "/root/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn filesystem_root_resolves_from_the_mount_point() {
        let starting_lookup_dir = StartingLookupDir::select(&FsType::Ext4, false, PathBuf::from("/boot"), default_unread).unwrap();
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
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
        assert_eq!(resolve(&starting_lookup_dir, "/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(resolve(&starting_lookup_dir, "/root"), Path::new("/top/snap1"));
        assert_eq!(resolve(&starting_lookup_dir, "//root/boot/grub2"), Path::new("/top/snap1/boot/grub2"));
    }

    #[test]
    fn exchange_maps_snapshot_paths_to_the_old_root() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(resolve(&starting_lookup_dir, "/snap1/boot/vmlinuz-6.19.9"), Path::new("/top/root/boot/vmlinuz-6.19.9"));
        assert_eq!(resolve(&starting_lookup_dir, "/snap1"), Path::new("/top/root"));
    }

    #[test]
    fn exchange_leaves_other_top_level_paths_alone() {
        let starting_lookup_dir = exchange_to("snap1");
        assert_eq!(resolve(&starting_lookup_dir, "/home/user"), Path::new("/top/home/user"));
        assert_eq!(resolve(&starting_lookup_dir, "/rootfs/boot"), Path::new("/top/rootfs/boot"));
        assert_eq!(resolve(&starting_lookup_dir, "/snap10/boot"), Path::new("/top/snap10/boot"));
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/top/vmlinuz-6.19.9"));
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
        assert_eq!(resolve(&starting_lookup_dir, "/root/boot/vmlinuz-6.19.9"),
            Path::new("/top/2025-01-02_03-04-05/boot/vmlinuz-6.19.9"));
    }

    #[test]
    fn after_rollback_from_top_level_exchanges_in_the_snapshot() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Btrfs, false, top(),
            &exchange_of_root_and("snap1"));
        assert_eq!(resolve(&starting_lookup_dir, "/root/boot/vmlinuz-6.19.9"), Path::new("/top/snap1/boot/vmlinuz-6.19.9"));
        assert_eq!(resolve(&starting_lookup_dir, "/home/user"), Path::new("/top/home/user"));
    }

    #[test]
    fn after_rollback_from_default_subvol_resolves_inside_the_snapshot() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Btrfs, true, top(),
            &exchange_of_root_and("snap1"));
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/top/snap1/vmlinuz-6.19.9"));
    }

    // /boot on its own filesystem is outside the snapshot: rollback leaves
    // it as it is, and GRUB reads it after the exchange as before.
    #[test]
    fn after_rollback_off_btrfs_resolves_on_the_live_boot_filesystem() {
        let starting_lookup_dir = StartingLookupDir::after_rollback(&FsType::Ext4, false, PathBuf::from("/boot"),
            &exchange_of_root_and("snap1"));
        assert_eq!(resolve(&starting_lookup_dir, "/vmlinuz-6.19.9"), Path::new("/boot/vmlinuz-6.19.9"));
        assert_eq!(resolve(&starting_lookup_dir, "/grub2/grub.cfg"), Path::new("/boot/grub2/grub.cfg"));
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

    // --- symbolic links, followed as GRUB follows them ---

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atomic-rollback-test-grub-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "contents").unwrap();
    }

    fn link(target: &str, at: &Path) {
        fs::create_dir_all(at.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(target, at).unwrap();
    }

    fn top_level(top: &Path) -> GrubContext {
        GrubContext::new(StartingLookupDir::BtrfsTopLevel { toplevel: top.to_path_buf(), exchange: None },
            "/root/boot/grub2".into())
    }

    fn boot_partition(boot: &Path) -> GrubContext {
        GrubContext::new(StartingLookupDir::FilesystemRoot(boot.to_path_buf()), "/grub2".into())
    }

    fn failure(grub: &GrubContext, grub_path: &str) -> Option<LookupFailure> {
        grub.find_file(grub_path).err().map(|e| e.failure)
    }

    /// Lays out file target in dir and links link1 .. link<n> to it, each
    /// to the one before, so a lookup of /link<n> follows n links.
    fn link_chain(dir: &Path, n: usize) {
        put(&dir.join("target"));
        for k in 1..=n {
            let to = if k == 1 { "target".to_string() } else { format!("link{}", k - 1) };
            link(&to, &dir.join(format!("link{k}")));
        }
    }

    #[test]
    fn absolute_link_restarts_at_the_starting_lookup_dir() {
        let top = scratch("link-absolute");
        put(&top.join("root/boot/vmlinuz"));
        link("/root/boot/vmlinuz", &top.join("root/vmlinuz"));

        assert_eq!(top_level(&top).find_file("/root/vmlinuz").ok(), Some(top.join("root/boot/vmlinuz")));
        fs::remove_dir_all(&top).unwrap();
    }

    // The target names a file on the running system, outside the
    // filesystem GRUB reads: GRUB looks for it below its own start.
    #[test]
    fn absolute_link_never_reaches_the_running_system() {
        let scratch_dir = scratch("link-escape");
        let top = scratch_dir.join("top");
        let outside = scratch_dir.join("outside/vmlinuz");
        put(&outside);
        link(outside.to_str().unwrap(), &top.join("vmlinuz"));

        assert_eq!(failure(&top_level(&top), "/vmlinuz"), Some(LookupFailure::FileNotFound));
        fs::remove_dir_all(&scratch_dir).unwrap();
    }

    #[test]
    fn relative_link_starts_at_its_directory_and_dotdot_stops_at_the_start() {
        let scratch_dir = scratch("link-relative");
        let boot = scratch_dir.join("boot");
        put(&boot.join("kernels/vmlinuz"));
        link("kernels/vmlinuz", &boot.join("vmlinuz"));
        link("../kernels/vmlinuz", &boot.join("efi/vmlinuz"));
        put(&scratch_dir.join("outside/vmlinuz"));
        link("../outside/vmlinuz", &boot.join("escape"));
        let grub = boot_partition(&boot);

        assert_eq!(grub.find_file("/vmlinuz").ok(), Some(boot.join("kernels/vmlinuz")));
        assert_eq!(grub.find_file("/efi/vmlinuz").ok(), Some(boot.join("kernels/vmlinuz")));
        assert_eq!(failure(&grub, "/escape"), Some(LookupFailure::FileNotFound));
        assert_eq!(failure(&grub, "/../outside/vmlinuz"), Some(LookupFailure::FileNotFound));
        fs::remove_dir_all(&scratch_dir).unwrap();
    }

    // grub-core/fs/btrfs.c, find_path: symlinks_max starts at 32 and the
    // lookup fails when it reaches 0.
    #[test]
    fn btrfs_follows_31_links_and_refuses_the_32nd() {
        let top = scratch("link-chain-btrfs");
        link_chain(&top, 32);
        let grub = top_level(&top);

        assert_eq!(grub.find_file("/link31").ok(), Some(top.join("target")));
        assert_eq!(failure(&grub, "/link32"), Some(LookupFailure::SymlinkLoop));
        fs::remove_dir_all(&top).unwrap();
    }

    // grub-core/fs/fshelp.c, find_file: the lookup fails when symlinknest
    // reaches 8.
    #[test]
    fn fshelp_follows_7_links_and_refuses_the_8th() {
        let boot = scratch("link-chain-fshelp");
        link_chain(&boot, 8);
        let grub = boot_partition(&boot);

        assert_eq!(grub.find_file("/link7").ok(), Some(boot.join("target")));
        assert_eq!(failure(&grub, "/link8"), Some(LookupFailure::SymlinkLoop));
        fs::remove_dir_all(&boot).unwrap();
    }

    // A file followed by more components: fshelp finds the file is not a
    // directory (fshelp.c, find_file); Btrfs refuses a regular file
    // followed by a slash as not found (btrfs.c, find_path).
    #[test]
    fn grub_opens_only_regular_files_and_walks_only_directories() {
        let top = scratch("file-types");
        put(&top.join("root/boot/vmlinuz"));

        for grub in [top_level(&top), boot_partition(&top)] {
            assert_eq!(failure(&grub, "/root/boot"), Some(LookupFailure::NotARegularFile));
        }
        assert_eq!(failure(&top_level(&top), "/root/boot/vmlinuz/initrd"), Some(LookupFailure::FileNotFound));
        assert_eq!(failure(&boot_partition(&top), "/root/boot/vmlinuz/initrd"), Some(LookupFailure::NotADirectory));
        fs::remove_dir_all(&top).unwrap();
    }

    // btrfs.c, find_path, refuses a regular file followed by a slash;
    // fshelp.c, find_file, skips trailing slashes.
    #[test]
    fn a_slash_after_a_regular_file_fails_only_on_btrfs() {
        let top = scratch("trailing-slash");
        put(&top.join("vmlinuz"));

        assert_eq!(failure(&top_level(&top), "/vmlinuz/"), Some(LookupFailure::FileNotFound));
        assert_eq!(boot_partition(&top).find_file("/vmlinuz/").ok(), Some(top.join("vmlinuz")));
        fs::remove_dir_all(&top).unwrap();
    }

    // On Btrfs, .. at the root of a subvolume stays there: each
    // subvolume's root directory names itself as parent (btrfs check
    // requires the inode ref, repair_fs_first_inode), and find_path follows
    // that ref. fshelp goes back up the path it walked.
    #[test]
    fn btrfs_dotdot_stays_at_a_subvolume_root() {
        let top = scratch("dotdot-subvolume");
        put(&top.join("root/vmlinuz"));
        put(&top.join("vmlinuz"));
        let root_subvol = top.join("root");
        let is_subvolume_root = |dir: &Path| dir == root_subvol.as_path();
        let btrfs = StartingLookupDir::BtrfsTopLevel { toplevel: top.clone(), exchange: None };
        let fshelp = StartingLookupDir::FilesystemRoot(top.clone());

        assert_eq!(btrfs.lookup("/root/../vmlinuz", is_subvolume_root).map(|(path, _)| path), Ok(top.join("root/vmlinuz")));
        assert_eq!(fshelp.lookup("/root/../vmlinuz", is_subvolume_root).map(|(path, _)| path), Ok(top.join("vmlinuz")));
        fs::remove_dir_all(&top).unwrap();
    }

    // fshelp does not see a FIFO (fshelp.c, find_file_iter skips an entry
    // of unknown type); Btrfs reaches it but cannot open it as a file.
    #[test]
    fn grub_does_not_open_a_fifo() {
        let top = scratch("fifo");
        let fifo = std::ffi::CString::new(top.join("vmlinuz").into_os_string().into_vec()).unwrap();
        // SAFETY: fifo is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        assert_eq!(failure(&boot_partition(&top), "/vmlinuz"), Some(LookupFailure::FileNotFound));
        assert_eq!(failure(&top_level(&top), "/vmlinuz"), Some(LookupFailure::NotARegularFile));
        fs::remove_dir_all(&top).unwrap();
    }

    // A link inside the snapshot whose target starts with the root
    // subvolume's name reaches the snapshot once the exchange is made.
    #[test]
    fn exchange_applies_to_link_targets() {
        let top = scratch("link-exchange");
        fs::create_dir_all(top.join("root")).unwrap();
        put(&top.join("snap1/boot/vmlinuz"));
        link("/root/boot/vmlinuz", &top.join("snap1/vmlinuz"));
        let grub = GrubContext::new(exchange_to_at(&top, "snap1"), "/root/boot/grub2".into());

        assert_eq!(grub.find_file("/root/vmlinuz").ok(), Some(top.join("snap1/boot/vmlinuz")));
        fs::remove_dir_all(&top).unwrap();
    }

    fn exchange_to_at(top: &Path, snapshot: &str) -> StartingLookupDir {
        StartingLookupDir::BtrfsTopLevel { toplevel: top.to_path_buf(), exchange: Some(exchange_of_root_and(snapshot)) }
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
