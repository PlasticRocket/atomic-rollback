//! Wrappers for external tools (btrfs-progs, blkid, findmnt, mount,
//! dracut, grub2-mkconfig, rsync) and fstab parsing helpers. Each
//! function delegates to a system tool and returns structured results.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;

use crate::consts::{BTRFS_TOPLEVEL_SUBVOLID, TEMPORARY_MOUNTPOINT_PARENT, TEMPORARY_MOUNTPOINT_TEMPLATE, TOPLEVEL_MOUNT};

/// Bare filesystem UUID extracted from BLS boot entries or grub2-probe.
/// Convert via into_device_spec() before passing to resolve_fstab_device
/// or get_mount_point.
#[derive(Debug, Clone)]
pub struct BareUuid(String);

impl BareUuid {
    pub fn new(s: String) -> Self { Self(s) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn into_device_spec(self) -> DeviceSpec {
        DeviceSpec::Uuid(self.0)
    }
}

/// Fstab device specification. Keeps the original format so it can be
/// written back to fstab.
#[derive(Debug, Clone)]
pub enum DeviceSpec {
    Uuid(String),
    Label(String),
    PartUuid(String),
    PartLabel(String),
    Id(String),
    Path(String),
}

impl DeviceSpec {
    /// Parse an fstab fs_spec field.
    pub fn parse(spec: &str) -> Self {
        if let Some(v) = spec.strip_prefix("UUID=") {
            Self::Uuid(v.to_string())
        } else if let Some(v) = spec.strip_prefix("LABEL=") {
            Self::Label(v.to_string())
        } else if let Some(v) = spec.strip_prefix("PARTUUID=") {
            Self::PartUuid(v.to_string())
        } else if let Some(v) = spec.strip_prefix("PARTLABEL=") {
            Self::PartLabel(v.to_string())
        } else if let Some(v) = spec.strip_prefix("ID=") {
            Self::Id(v.to_string())
        } else {
            Self::Path(spec.to_string())
        }
    }

}

impl std::fmt::Display for DeviceSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uuid(v) => write!(f, "UUID={v}"),
            Self::Label(v) => write!(f, "LABEL={v}"),
            Self::PartUuid(v) => write!(f, "PARTUUID={v}"),
            Self::PartLabel(v) => write!(f, "PARTLABEL={v}"),
            Self::Id(v) => write!(f, "ID={v}"),
            Self::Path(v) => write!(f, "{v}"),
        }
    }
}

/// Resolved /dev/ path.
#[derive(Debug, Clone)]
pub struct DevicePath(String);

impl DevicePath {
    pub fn new(s: String) -> Self { Self(s) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn into_device_spec(self) -> DeviceSpec {
        DeviceSpec::Path(self.0)
    }
}

/// Btrfs subvolume name (e.g., "root", "home", "var", "root.pre-update").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubvolName(String);

impl SubvolName {
    pub fn new(s: String) -> Self { Self(s) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl std::fmt::Display for SubvolName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Flush all pending filesystem changes to disk.
/// Btrfs operations (RENAME_EXCHANGE, set-default) use btrfs_end_transaction,
/// which commits to the in-memory journal but NOT to disk. Changes are lost
/// on power failure until the next btrfs transaction commit (up to 30s).
/// syncfs forces the commit.
#[cfg(target_os = "linux")]
pub fn sync_filesystem(path: &str) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let f = fs::File::open(path)
        .map_err(|e| format!("open {path} for sync: {e}"))?;
    let ret = unsafe { libc::syncfs(f.as_raw_fd()) };
    if ret == 0 {
        Ok(())
    } else {
        Err(format!("syncfs {path}: {}", std::io::Error::last_os_error()))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn sync_filesystem(_path: &str) -> Result<(), String> {
    unreachable!("atomic-rollback is a Linux-only tool")
}

/// Runs a command and returns stdout as a trimmed string. Fails on non-zero exit.
/// Uses from_utf8_lossy: all wrapped tools (btrfs, blkid, findmnt) produce ASCII.
pub fn run_stdout(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd).args(args).output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{cmd} {}: {stderr}", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Runs a command. On failure, includes stderr in the error message.
fn run_ok(cmd: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(cmd).args(args).output()
        .map_err(|e| format!("{cmd}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("{cmd} {}: {stderr}", args.join(" ")))
    }
}

// --- blkid ---

/// Returns the block device path for a filesystem UUID (e.g. "UUID" -> "/dev/sda2").
pub fn blkid_device_for_uuid(uuid: &BareUuid) -> Result<DevicePath, String> {
    run_stdout("blkid", &["--uuid", uuid.as_str()]).map(DevicePath::new)
}

/// Resolves a /dev/disk/ symlink to the real device path.
fn resolve_udev_symlink(subdir: &str, value: &str) -> Result<DevicePath, String> {
    let link = format!("/dev/disk/{subdir}/{value}");
    let real = fs::canonicalize(&link)
        .map_err(|e| format!("{link}: {e}"))?;
    Ok(DevicePath::new(real.to_string_lossy().to_string()))
}

/// Resolves a fstab device field to a block device path.
/// Handles all six mount(8) tag formats defined in libmount's
/// mnt_valid_tagname() (libmount/src/utils.c:47): UUID=, LABEL=,
/// PARTUUID=, PARTLABEL=, ID=, and raw /dev/ paths.
/// PARTUUID/PARTLABEL/ID resolve via /dev/disk/ symlinks
/// (udev 60-persistent-storage.rules).
/// Note: systemd fstab-generator only handles four tags (no ID=).
/// ID= in fstab works with mount(8) but not with systemd boot.
pub fn resolve_fstab_device(device: &DeviceSpec) -> Result<DevicePath, String> {
    match device {
        DeviceSpec::Uuid(uuid) => blkid_device_for_uuid(&BareUuid::new(uuid.clone())),
        DeviceSpec::Label(label) =>
            run_stdout("blkid", &["-L", label]).map(DevicePath::new),
        DeviceSpec::PartUuid(v) => resolve_udev_symlink("by-partuuid", v),
        DeviceSpec::PartLabel(v) => resolve_udev_symlink("by-partlabel", v),
        DeviceSpec::Id(v) => resolve_udev_symlink("by-id", v),
        DeviceSpec::Path(p) => Ok(DevicePath::new(p.clone())),
    }
}

/// Filesystem type. The name string is defined by each kernel filesystem
/// driver (e.g. fs/btrfs/super.c: .name = "btrfs"). Variants for types
/// the tool discriminates on; everything else in Other.
#[derive(PartialEq)]
pub enum FsType {
    Btrfs,
    Ext4,
    Swap,
    Other(String),
}

/// Parses a filesystem type name string into FsType.
pub fn parse_fstype(name: &str) -> FsType {
    match name {
        "btrfs" => FsType::Btrfs,
        "ext4" => FsType::Ext4,
        "swap" => FsType::Swap,
        _ => FsType::Other(name.to_string()),
    }
}

/// Returns the filesystem type on a block device.
pub fn blkid_fstype(device: &DevicePath) -> Result<FsType, String> {
    let name = run_stdout("blkid", &["-s", "TYPE", "-o", "value", device.as_str()])?;
    Ok(parse_fstype(&name))
}

// --- findmnt ---

/// Find the mount point of a device.
/// Accepts any device spec findmnt supports: UUID=, LABEL=, PARTUUID=,
/// PARTLABEL=, /dev/ path (findmnt(8) source specification).
/// - ext4/vfat: single mount point (e.g., /boot). Return it.
/// - Btrfs: multiple mount points (/, /home, /var). Return / specifically,
///   where the root subvolume is mounted. GRUB does not necessarily
///   resolve paths from there (see grub.rs).
pub fn findmnt_target(device_spec: &DeviceSpec) -> Result<String, String> {
    let spec_str = device_spec.to_string();
    let out = run_stdout("findmnt", &["-n", "-o", "TARGET", "-S", &spec_str])?;
    let targets: Vec<&str> = out.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    match targets.len() {
        0 => Err(format!("{spec_str} not mounted")),
        1 => Ok(targets[0].to_string()),
        _ => {
            targets.iter()
                .find(|&&t| t == "/")
                .map(|t| t.to_string())
                .ok_or_else(|| format!("{spec_str} mounted at {targets:?} but not at /"))
        }
    }
}

/// Checks whether a path is an active mount point.
pub fn is_mountpoint(path: &Path) -> bool {
    Command::new("mountpoint").arg("-q").arg(path).status()
        .is_ok_and(|s| s.success())
}

// --- btrfs ---

/// Parsed btrfs subvolume entry. Derived from the output grammar:
///   "ID " u64 " gen " u64 " top level " u64 " path " string "\n"
/// Source: cmds/subvolume-list.c:1249 (list), cmds/subvolume.c:822 (get-default).
pub struct SubvolEntry {
    pub id: u64,
    pub path: String,
    // Parsed for format validation, not currently consumed.
    pub _generation: u64,
    pub _top_level: u64,
}

/// Parses one line of btrfs subvolume list/get-default output.
/// Uses sentinel-based extraction (not whitespace splitting) because
/// the path field can contain spaces.
fn parse_subvol_line(line: &str) -> Option<SubvolEntry> {
    let rest = line.strip_prefix("ID ")?;
    let (id_str, rest) = rest.split_once(" gen ")?;
    let (gen_str, rest) = rest.split_once(" top level ")?;
    let (top_str, path) = rest.split_once(" path ")?;
    Some(SubvolEntry {
        id: id_str.parse().ok()?,
        _generation: gen_str.parse().ok()?,
        _top_level: top_str.parse().ok()?,
        path: path.to_string(),
    })
}

/// Lists all subvolumes on the filesystem containing mount_point.
pub fn btrfs_subvol_list(mount_point: &str) -> Result<Vec<SubvolEntry>, String> {
    let out = run_stdout("btrfs", &["subvolume", "list", mount_point])?;
    out.lines()
        .map(|line| parse_subvol_line(line)
            .ok_or_else(|| format!("cannot parse subvol line: {line}")))
        .collect()
}

/// A subvolume with its origin generation (ogen): the filesystem
/// generation in which the subvolume was created (btrfs-subvolume(8),
/// list -c). Creation order is ogen order; btrfs promises no order of IDs.
/// Output grammar of `btrfs subvolume list -c`:
///   "ID " u64 " gen " u64 " cgen " u64 " top level " u64 " path " string "\n"
pub struct SubvolOgen {
    pub id: u64,
    pub ogen: u64,
    pub path: String,
}

/// Parses one line of `btrfs subvolume list -c` output. Sentinel-based
/// like parse_subvol_line, because the path can contain spaces.
fn parse_subvol_ogen_line(line: &str) -> Option<SubvolOgen> {
    let rest = line.strip_prefix("ID ")?;
    let (id_str, rest) = rest.split_once(" gen ")?;
    let (_gen_str, rest) = rest.split_once(" cgen ")?;
    let (ogen_str, rest) = rest.split_once(" top level ")?;
    let (_top_str, path) = rest.split_once(" path ")?;
    Some(SubvolOgen {
        id: id_str.parse().ok()?,
        ogen: ogen_str.parse().ok()?,
        path: path.to_string(),
    })
}

/// Lists all subvolumes on the filesystem containing mount_point, with
/// their origin generations.
pub fn btrfs_subvol_list_ogen(mount_point: &str) -> Result<Vec<SubvolOgen>, String> {
    let out = run_stdout("btrfs", &["subvolume", "list", "-c", mount_point])?;
    out.lines()
        .map(|line| parse_subvol_ogen_line(line)
            .ok_or_else(|| format!("cannot parse subvol line: {line}")))
        .collect()
}

/// The default subvolume, as btrfs subvolume get-default reports it.
pub enum DefaultSubvol {
    /// The top-level subvolume itself.
    TopLevel,
    /// Another subvolume. Its path is relative to the top-level subvolume.
    Subvol(SubvolEntry),
}

impl DefaultSubvol {
    pub fn id(&self) -> u64 {
        match self {
            DefaultSubvol::TopLevel => BTRFS_TOPLEVEL_SUBVOLID,
            DefaultSubvol::Subvol(entry) => entry.id,
        }
    }

    /// Path below the top-level subvolume; empty for the top level itself.
    pub fn path(&self) -> &str {
        match self {
            DefaultSubvol::TopLevel => "",
            DefaultSubvol::Subvol(entry) => &entry.path,
        }
    }
}

/// Two productions (cmds/subvolume.c:789-823):
///   FS_TREE: literal "ID 5 (FS_TREE)" -> TopLevel
///   Subvol:  standard subvol line format, path from the top level -> Subvol
fn parse_default_subvol(out: &str) -> Option<DefaultSubvol> {
    if let Some(entry) = parse_subvol_line(out) {
        return Some(DefaultSubvol::Subvol(entry));
    }
    (out.trim() == "ID 5 (FS_TREE)").then_some(DefaultSubvol::TopLevel)
}

/// Returns the default subvolume for the filesystem at mount_point.
pub fn btrfs_subvol_get_default(mount_point: &str) -> Result<DefaultSubvol, String> {
    let out = run_stdout("btrfs", &["subvolume", "get-default", mount_point])?;
    parse_default_subvol(&out)
        .ok_or_else(|| format!("cannot parse default subvol ID from: {out}"))
}

/// Whether path is the root directory of a Btrfs subvolume, by
/// libbtrfsutil's test (btrfs_util_is_subvolume): a directory on a Btrfs
/// filesystem whose inode number is BTRFS_FIRST_FREE_OBJECTID.
#[cfg(target_os = "linux")]
pub fn is_btrfs_subvolume_root(path: &Path) -> std::io::Result<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    use crate::consts::BTRFS_FIRST_FREE_OBJECTID;

    let c_path = CString::new(path.as_os_str().as_bytes())?;
    let mut sfs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs reads the NUL-terminated c_path and writes only into
    // sfs, which has the size and alignment of a statfs.
    if unsafe { libc::statfs(c_path.as_ptr(), sfs.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: statfs returned 0, so it filled sfs.
    let sfs = unsafe { sfs.assume_init() };
    if sfs.f_type != libc::BTRFS_SUPER_MAGIC {
        return Ok(false);
    }
    let meta = fs::metadata(path)?;
    Ok(meta.is_dir() && meta.ino() == BTRFS_FIRST_FREE_OBJECTID)
}

#[cfg(not(target_os = "linux"))]
pub fn is_btrfs_subvolume_root(_path: &Path) -> std::io::Result<bool> {
    Ok(false)
}

// Btrfs ioctls (include/uapi/linux/btrfs.h). Request numbers are built as
// include/uapi/asm-generic/ioctl.h builds them, which x86_64 and aarch64,
// the architectures the package is built for, both use.
#[cfg(target_os = "linux")]
const BTRFS_IOCTL_MAGIC: u64 = 0x94;
#[cfg(target_os = "linux")]
const IOC_WRITE: u64 = 1;
#[cfg(target_os = "linux")]
const IOC_READ: u64 = 2;

#[cfg(target_os = "linux")]
const fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | (BTRFS_IOCTL_MAGIC << 8) | nr
}

// struct btrfs_ioctl_ino_lookup_args.
#[cfg(target_os = "linux")]
const BTRFS_INO_LOOKUP_PATH_MAX: usize = 4080;
#[cfg(target_os = "linux")]
#[repr(C)]
struct BtrfsIoctlInoLookupArgs {
    treeid: u64,
    objectid: u64,
    _name: [u8; BTRFS_INO_LOOKUP_PATH_MAX],
}
#[cfg(target_os = "linux")]
const BTRFS_IOC_INO_LOOKUP: u64 =
    ioc(IOC_READ | IOC_WRITE, 18, std::mem::size_of::<BtrfsIoctlInoLookupArgs>());

/// The ID of the subvolume containing path, as libbtrfsutil's
/// btrfs_util_subvolume_id_fd finds it (btrfs-progs
/// libbtrfsutil/subvolume.c): BTRFS_IOC_INO_LOOKUP of the subvolume's root
/// directory (BTRFS_FIRST_FREE_OBJECTID) with treeid 0, which the kernel
/// fills with the subvolume's ID.
#[cfg(target_os = "linux")]
pub fn btrfs_subvolume_id(path: &str) -> Result<u64, String> {
    use std::os::fd::AsRawFd;
    use crate::consts::BTRFS_FIRST_FREE_OBJECTID;

    let dir = fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut args = BtrfsIoctlInoLookupArgs {
        treeid: 0,
        objectid: BTRFS_FIRST_FREE_OBJECTID,
        _name: [0; BTRFS_INO_LOOKUP_PATH_MAX],
    };
    // SAFETY: args is a btrfs_ioctl_ino_lookup_args, the size the request
    // number encodes, and the kernel writes only within it.
    let ret = unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_INO_LOOKUP as libc::Ioctl, &mut args) };
    if ret != 0 {
        return Err(format!("BTRFS_IOC_INO_LOOKUP {path}: {}", std::io::Error::last_os_error()));
    }
    Ok(args.treeid)
}

#[cfg(not(target_os = "linux"))]
pub fn btrfs_subvolume_id(_path: &str) -> Result<u64, String> {
    unreachable!("atomic-rollback is a Linux-only tool")
}

/// Sets the default subvolume for the filesystem at mount_point.
pub fn btrfs_subvol_set_default(id: u64, mount_point: &str) -> Result<(), String> {
    run_ok("btrfs", &["subvolume", "set-default", &id.to_string(), mount_point])
}

/// Creates a btrfs snapshot of src at dst.
/// Captures stdout to prevent btrfs output from interfering with the caller.
pub fn btrfs_subvol_snapshot(src: &str, dst: &str) -> Result<(), String> {
    run_stdout("btrfs", &["subvolume", "snapshot", src, dst]).map(|_| ())
}

/// Returns the creation time of a subvolume as a local-time string (%Y-%m-%d %H:%M:%S).
/// The path must be the full path to the subvolume (e.g., via a toplevel mount).
pub fn btrfs_subvol_creation_time(path: &str) -> Result<String, String> {
    let out = run_stdout("btrfs", &["subvolume", "show", path])?;
    for line in out.lines() {
        let line = line.trim();
        if let Some(raw) = line.strip_prefix("Creation time:") {
            let raw = raw.trim();
            // Drop the timezone suffix (e.g., " -0700") to get local-time datetime
            let datetime = raw.rsplit_once(' ').map(|(dt, _tz)| dt).unwrap_or(raw);
            return Ok(datetime.to_string());
        }
    }
    Err(format!("no creation time found in btrfs subvolume show output for {path}"))
}

/// Looks up a subvolume's ID by name.
pub fn btrfs_subvol_id_by_name(mount_point: &str, name: &SubvolName) -> Result<u64, String> {
    let entries = btrfs_subvol_list(mount_point)?;
    entries.iter()
        .find(|e| e.path == name.as_str())
        .map(|e| e.id)
        .ok_or_else(|| format!("subvol '{}' not found on {mount_point}", name.as_str()))
}

// --- mount/umount ---

pub fn mount_ro(device: &DevicePath, target: &str) -> Result<(), String> {
    run_ok("mount", &["-o", "ro", device.as_str(), target])
}

pub fn mount_subvolid(device: &DevicePath, target: &str, subvolid: u64) -> Result<(), String> {
    run_ok("mount", &["-o", &format!("subvolid={subvolid}"), device.as_str(), target])
}

/// Mounts the top-level subvolume (subvolid=5) of the Btrfs filesystem on
/// device read-only at a temporary mount point, apart from TOPLEVEL_MOUNT.
/// Unmounted when the MountPoint drops.
pub fn mount_toplevel_ro(device: &DevicePath) -> Result<MountPoint, String> {
    mount_temporary(device, &format!("ro,subvolid={BTRFS_TOPLEVEL_SUBVOLID}"))
}

/// Mounts device with the given options at a new temporary mount point.
fn mount_temporary(device: &DevicePath, options: &str) -> Result<MountPoint, String> {
    let dir = make_temporary_mountpoint(Path::new(TEMPORARY_MOUNTPOINT_PARENT))?;
    // mkdtemp's suffix is ASCII, so the conversion is lossless.
    let dir = dir.to_string_lossy().into_owned();
    if let Err(e) = run_ok("mount", &["-o", options, device.as_str(), &dir]) {
        let _ = fs::remove_dir(&dir);
        return Err(e);
    }
    Ok(MountPoint::Temporary(dir))
}

/// Creates a new directory under parent named from TEMPORARY_MOUNTPOINT_TEMPLATE,
/// with mkdtemp(3): the name gets a unique suffix, and the directory is
/// created in one step with mode 0700. An existing entry of the same name,
/// a symlink included, makes mkdtemp pick another name; it is never reused
/// or followed.
fn make_temporary_mountpoint(parent: &Path) -> Result<PathBuf, String> {
    use std::ffi::{CString, OsString};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};

    let template = parent.join(TEMPORARY_MOUNTPOINT_TEMPLATE);
    let mut buf = CString::new(template.as_os_str().as_bytes())
        .map_err(|_| format!("temporary mount point template {} contains a NUL byte", template.display()))?
        .into_bytes_with_nul();
    // SAFETY: buf is a writable, NUL-terminated buffer that mkdtemp
    // rewrites in place; it is read only after a successful return.
    let created = unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) };
    if created.is_null() {
        return Err(format!("mkdtemp {}: {}", template.display(), std::io::Error::last_os_error()));
    }
    buf.pop(); // the NUL terminator
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Whether the process runs with root's effective UID, which mount(8)
/// requires.
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail (geteuid(2)).
    unsafe { libc::geteuid() == 0 }
}

pub fn umount(target: &str) -> Result<(), String> {
    run_ok("umount", &[target])
}

// --- dracut ---

pub fn dracut_rebuild(output: &str, kver: &str) -> Result<(), String> {
    run_ok("dracut", &[output, kver])
}

// --- grub ---

/// ESP grub.cfg stub contract. Derived from gen_grub_cfgstub
/// (/usr/bin/gen_grub_cfgstub).
/// The generator's inputs are boot_uuid and grub_dir.
/// btrfs_relative is added by our migration.
pub struct EspStub {
    pub boot_uuid: BareUuid,
    pub grub_dir: String,
    pub btrfs_relative: bool,
}

/// Extracts the generator's contract values from an ESP grub.cfg.
/// The script format varies across versions; we extract by content,
/// not by line position.
pub fn parse_esp_stub(content: &str) -> Result<EspStub, String> {
    // UUID is the final positional argument to GRUB's search command
    // (search_wrap.c:176,218: "NAME" is the last arg after flags).
    // gen_grub_cfgstub places ${BOOT_UUID} at end of the line.
    let boot_uuid = content.lines()
        .find(|l| l.contains("--fs-uuid"))
        .and_then(|l| l.split_whitespace().last())
        .map(|s| BareUuid::new(s.to_string()))
        .ok_or("ESP grub.cfg: no search --fs-uuid line")?;

    let grub_dir = content.lines()
        .find(|l| l.contains("prefix="))
        .and_then(|l| {
            // "set prefix=($dev)/boot/grub2" -> "/boot/grub2"
            let after_paren = l.split(')').nth(1)?;
            Some(after_paren.trim().to_string())
        })
        .ok_or("ESP grub.cfg: no prefix= line")?;

    let btrfs_relative = btrfs_relative_path_is_set(stub_assignment(content, "btrfs_relative_path"));

    Ok(EspStub { boot_uuid, grub_dir, btrfs_relative })
}

/// Whether GRUB's Btrfs driver resolves paths from the default subvolume
/// with btrfs_relative_path holding value: it tests only the first
/// character, for '1' or 'y' (Fedora's grub2 2.12 patches,
/// grub-core/fs/btrfs.c, grub_btrfs_mount and find_path).
pub fn btrfs_relative_path_is_set(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.starts_with(['1', 'y']))
}

/// The value the ESP stub leaves in the variable name when configfile
/// hands over to grub.cfg: the stub runs top to bottom, so its last
/// assignment before the configfile line holds.
pub fn stub_assignment<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    before_configfile(content).filter_map(|line| grub_assignment(line, name)).last()
}

/// The stub's lines before the one running configfile, which hands over
/// to grub.cfg: GRUB runs grub.cfg with the variables these lines set.
pub fn before_configfile(content: &str) -> impl Iterator<Item = &str> {
    content.lines().take_while(|line| line.split_whitespace().next() != Some("configfile"))
}

/// The value a GRUB script line assigns to the variable name, either as
/// "set <name>=<value>" or "<name>=<value>", with its quotes removed.
pub fn grub_assignment<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let line = line.trim();
    let assignment = line.strip_prefix("set ").map_or(line, str::trim_start);
    let value = assignment.strip_prefix(name)?.strip_prefix('=')?;
    Some(value.trim_matches(|c| c == '"' || c == '\''))
}

/// Renders an ESP grub.cfg stub from the contract values.
/// Template matches gen_grub_cfgstub (/usr/bin/gen_grub_cfgstub).
/// Variable is $dev to match the generator (--set=dev).
pub fn render_esp_stub(stub: &EspStub) -> String {
    let mut lines = Vec::new();
    if stub.btrfs_relative {
        lines.push("set btrfs_relative_path=\"yes\"".to_string());
    }
    lines.push(format!(
        "search --no-floppy --root-dev-only --fs-uuid --set=dev {}", stub.boot_uuid.as_str()));
    lines.push(format!("set prefix=($dev){}", stub.grub_dir));
    lines.push("export $prefix".to_string());
    lines.push("configfile $prefix/grub.cfg".to_string());
    lines.join("\n") + "\n"
}

pub fn grub2_mkconfig(output: &str) -> Result<(), String> {
    run_ok("grub2-mkconfig", &["-o", output])
}

// --- rsync ---

pub fn rsync(src: &str, dst: &str) -> Result<(), String> {
    run_ok("rsync", &["-a", src, dst])
}

// --- fstab ---

/// Parsed fstab line. Derived from the fstab(5) grammar:
///   line ::= comment | blank | entry
///   entry ::= fs_spec ws fs_file ws fs_vfstype ws fs_mntops [ws fs_freq [ws fs_passno]]
/// Entry fields mirror struct mntent from getmntent(3).
/// Octal escapes (\040, \011, \012, \\) decoded per fstab(5).
pub enum FstabLine {
    Comment(String),
    Blank(String),
    Entry(FstabEntry),
}

impl FstabLine {
    pub fn raw(&self) -> &str {
        match self {
            FstabLine::Comment(s) | FstabLine::Blank(s) => s,
            FstabLine::Entry(e) => &e.raw,
        }
    }
}

pub struct FstabEntry {
    pub fs_spec: DeviceSpec,
    pub fs_file: String,
    pub fs_vfstype: FsType,
    pub fs_mntops: String,
    pub raw: String,
    // Parsed for format validation, not currently consumed.
    pub _fs_freq: i32,
    pub _fs_passno: i32,
}

/// Decodes fstab octal escapes: \040 (space), \011 (tab), \012 (newline),
/// \134 (backslash). Per getmntent(3).
fn fstab_decode(field: &str) -> String {
    let mut result = String::with_capacity(field.len());
    let mut chars = field.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let escape: String = chars.by_ref().take(3).collect();
            match escape.as_str() {
                "040" => result.push(' '),
                "011" => result.push('\t'),
                "012" => result.push('\n'),
                "134" => result.push('\\'),
                _ => { result.push('\\'); result.push_str(&escape); }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Parses fstab content into the full grammar: comments, blanks, and entries.
/// Fields 5-6 default to 0 per fstab(5).
pub fn parse_fstab(content: &str) -> Vec<FstabLine> {
    content.lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                FstabLine::Blank(line.to_string())
            } else if trimmed.starts_with('#') {
                FstabLine::Comment(line.to_string())
            } else {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 4 {
                    FstabLine::Comment(line.to_string()) // malformed, preserve as-is
                } else {
                    FstabLine::Entry(FstabEntry {
                        fs_spec: DeviceSpec::parse(&fstab_decode(fields[0])),
                        fs_file: fstab_decode(fields[1]),
                        fs_vfstype: parse_fstype(fields[2]),
                        fs_mntops: fields[3].to_string(),
                        raw: line.to_string(),
                        _fs_freq: fields.get(4).and_then(|f| f.parse().ok()).unwrap_or(0),
                        _fs_passno: fields.get(5).and_then(|f| f.parse().ok()).unwrap_or(0),
                    })
                }
            }
        })
        .collect()
}

/// Returns only the entries from parsed fstab lines.
pub fn fstab_entries(lines: &[FstabLine]) -> Vec<&FstabEntry> {
    lines.iter().filter_map(|l| match l {
        FstabLine::Entry(e) => Some(e),
        _ => None,
    }).collect()
}

/// Read /etc/fstab and return the root device path (resolved from UUID=/LABEL=/dev path).
pub fn root_device() -> Result<(DevicePath, String), String> {
    let content = fs::read_to_string("/etc/fstab")
        .map_err(|e| format!("Cannot read /etc/fstab: {e}"))?;
    let lines = parse_fstab(&content);
    let root = fstab_entries(&lines).into_iter()
        .find(|e| e.fs_file == "/")
        .ok_or("Cannot find root entry in /etc/fstab")?;
    let device = resolve_fstab_device(&root.fs_spec)?;
    Ok((device, content))
}

/// Extract the root subvolume name from fstab (the subvol= value for /).
pub fn root_subvol_name(fstab: &str) -> Result<SubvolName, String> {
    let lines = parse_fstab(fstab);
    fstab_entries(&lines).into_iter()
        .find(|e| e.fs_file == "/")
        .and_then(|e| crate::parse::extract_mount_option(&e.fs_mntops, "subvol"))
        .map(|s| SubvolName::new(s.to_string()))
        .ok_or_else(|| "Cannot determine root subvolume name from /etc/fstab".into())
}

/// Mount the top-level subvolume (subvolid=5), run a closure, unmount.
/// Guarantees unmount on both success and failure.
pub fn with_toplevel<F, T>(f: F) -> Result<T, String>
where
    F: FnOnce(&str) -> Result<T, String>,
{
    let toplevel = TOPLEVEL_MOUNT;
    let (device, _) = root_device()?;

    fs::create_dir_all(toplevel).map_err(|e| format!("mkdir {toplevel}: {e}"))?;
    mount_subvolid(&device, toplevel, BTRFS_TOPLEVEL_SUBVOLID)?;

    let result = f(toplevel);

    // Best-effort cleanup. A stale mount or temp dir persists until
    // reboot but does not affect the boot chain.
    let _ = umount(toplevel);
    let _ = fs::remove_dir(toplevel);

    result
}

// --- BLS entry ---

/// Parsed Boot Loader Specification entry line.
/// Derived from the BLS grammar (uapi-group.org/specifications/specs/boot_loader_specification):
///   line ::= comment | blank | field
///   field ::= key whitespace value
/// Value is everything after the first delimiter (blsuki.c:316, grub_strtok_r).
/// initrd may appear on multiple lines (BLS spec).
/// prefix stores key + original whitespace so transformers preserve formatting.
pub enum BlsLine {
    Comment(String),
    Blank(String),
    Field { key: String, value: String, prefix: String },
}

impl BlsLine {
    /// Reconstructs the original line text. Lossless for all variants.
    pub fn raw(&self) -> String {
        match self {
            BlsLine::Comment(s) | BlsLine::Blank(s) => s.clone(),
            BlsLine::Field { prefix, value, .. } => format!("{prefix}{value}"),
        }
    }
}

/// Parses BLS entry content into the full grammar.
pub fn parse_bls(content: &str) -> Vec<BlsLine> {
    content.lines()
        .map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                BlsLine::Blank(line.to_string())
            } else if trimmed.starts_with('#') {
                BlsLine::Comment(line.to_string())
            } else if let Some(sep_pos) = trimmed.find(|c: char| c == ' ' || c == '\t') {
                let key = trimmed[..sep_pos].to_string();
                let rest = &trimmed[sep_pos..];
                let value_start = rest.len() - rest.trim_start().len();
                let prefix_len = sep_pos + value_start;
                BlsLine::Field {
                    key,
                    value: trimmed[prefix_len..].to_string(),
                    prefix: trimmed[..prefix_len].to_string(),
                }
            } else {
                // Key with no value
                BlsLine::Field {
                    key: trimmed.to_string(),
                    value: String::new(),
                    prefix: trimmed.to_string(),
                }
            }
        })
        .collect()
}

// --- temporary mount point: mount a device if not already mounted ---

/// Accepts any fstab device spec (UUID=, LABEL=, PARTUUID=, PARTLABEL=,
/// ID=, /dev/ path). Checks findmnt first; if not mounted, resolves to
/// a device path and mounts it read-only at a temporary mount point.
pub fn get_mount_point(device_spec: &DeviceSpec) -> Result<MountPoint, String> {
    if let Ok(target) = findmnt_target(device_spec) {
        if !target.is_empty() {
            return Ok(MountPoint::Existing(target));
        }
    }

    let device = resolve_fstab_device(device_spec)?;
    mount_temporary(&device, "ro")
}

/// A filesystem mount point, either already mounted or mounted by this tool
/// at a temporary mount point, which is unmounted on drop.
pub enum MountPoint {
    /// Already mounted by the system (e.g. / or /home).
    Existing(String),
    /// Mounted by this tool for inspection, at a temporary mount point.
    Temporary(String),
}

impl MountPoint {
    pub fn path(&self) -> &str {
        match self {
            MountPoint::Existing(p) | MountPoint::Temporary(p) => p,
        }
    }
}

impl Drop for MountPoint {
    fn drop(&mut self) {
        if let MountPoint::Temporary(p) = self {
            // Best-effort. Failure means the mount persists until reboot.
            let _ = Command::new("umount").arg(p.as_str()).output();
            let _ = fs::remove_dir(p.as_str());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- temporary mount points ---

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atomic-rollback-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn temporary_mountpoint_name_matches_template(name: &str) -> bool {
        let prefix = TEMPORARY_MOUNTPOINT_TEMPLATE.trim_end_matches('X');
        let suffix_len = TEMPORARY_MOUNTPOINT_TEMPLATE.len() - prefix.len();
        name.strip_prefix(prefix).is_some_and(|suffix|
            suffix.len() == suffix_len && suffix.bytes().all(|b| b.is_ascii_alphanumeric()))
    }

    // A temporary mount point is one this call created: a real directory,
    // not a pre-existing entry, private to its owner, empty, under parent.
    fn assert_fresh_temporary_mountpoint(parent: &Path, dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(dir.parent(), Some(parent));
        let name = dir.file_name().unwrap().to_str().unwrap();
        assert!(temporary_mountpoint_name_matches_template(name), "{name}");
        let meta = fs::symlink_metadata(dir).unwrap();
        assert!(meta.file_type().is_dir(), "{} is not a directory", dir.display());
        assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        assert!(fs::read_dir(dir).unwrap().next().is_none());
    }

    #[test]
    fn temporary_mountpoint_is_created_fresh_under_its_parent() {
        let parent = scratch("temporary-mountpoint-fresh");
        let first = make_temporary_mountpoint(&parent).unwrap();
        let second = make_temporary_mountpoint(&parent).unwrap();
        assert_ne!(first, second);
        assert_fresh_temporary_mountpoint(&parent, &first);
        assert_fresh_temporary_mountpoint(&parent, &second);
        fs::remove_dir_all(&parent).unwrap();
    }

    // Entries another user could have prepared, under the names a
    // predictable scheme would pick: none is ever returned or followed.
    #[test]
    fn temporary_mountpoint_never_reuses_an_existing_entry() {
        let parent = scratch("temporary-mountpoint-existing");
        let elsewhere = scratch("temporary-mountpoint-existing-target");
        let prefix = TEMPORARY_MOUNTPOINT_TEMPLATE.trim_end_matches('X');
        let planted = [
            parent.join(TEMPORARY_MOUNTPOINT_TEMPLATE),
            parent.join(format!("{prefix}toplevel-b7f6a24")),
            parent.join(format!("{prefix}AAAAAA")),
        ];
        std::os::unix::fs::symlink(&elsewhere, &planted[0]).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &planted[1]).unwrap();
        fs::create_dir(&planted[2]).unwrap();

        for _ in 0..64 {
            let dir = make_temporary_mountpoint(&parent).unwrap();
            assert!(!planted.contains(&dir), "reused {}", dir.display());
            assert_fresh_temporary_mountpoint(&parent, &dir);
        }
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
        fs::remove_dir_all(&parent).unwrap();
        fs::remove_dir_all(&elsewhere).unwrap();
    }

    #[test]
    fn temporary_mountpoint_reports_a_missing_parent() {
        let scratch_dir = scratch("temporary-mountpoint-missing");
        assert!(make_temporary_mountpoint(&scratch_dir.join("absent")).is_err());
        fs::remove_dir_all(&scratch_dir).unwrap();
    }

    // The production parent refuses entries from users other than root,
    // which is what keeps them from preparing a mount point there.
    #[cfg(target_os = "linux")]
    #[test]
    fn temporary_mountpoint_parent_is_writable_only_by_root() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::metadata(TEMPORARY_MOUNTPOINT_PARENT).unwrap();
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.permissions().mode() & 0o022, 0, "{TEMPORARY_MOUNTPOINT_PARENT} is group or world writable");
        if !is_root() {
            assert!(make_temporary_mountpoint(Path::new(TEMPORARY_MOUNTPOINT_PARENT)).is_err());
        }
    }

    #[test]
    fn default_subvol_parses_a_subvolume() {
        let default = parse_default_subvol("ID 273 gen 98765 top level 5 path root").unwrap();
        assert_eq!(default.id(), 273);
        assert_eq!(default.path(), "root");
    }

    #[test]
    fn default_subvol_parses_the_top_level() {
        let default = parse_default_subvol("ID 5 (FS_TREE)").unwrap();
        assert_eq!(default.id(), BTRFS_TOPLEVEL_SUBVOLID);
        assert_eq!(default.path(), "");
    }

    #[test]
    fn default_subvol_rejects_other_output() {
        assert!(parse_default_subvol("ERROR: not a btrfs filesystem").is_none());
    }

    // Lines as btrfs-progs 7.1 prints them for `btrfs subvolume list -c`.
    #[test]
    fn subvol_ogen_reads_the_creation_generation() {
        let entry = parse_subvol_ogen_line("ID 256 gen 362 cgen 9 top level 5 path root").unwrap();
        assert_eq!((entry.id, entry.ogen, entry.path.as_str()), (256, 9, "root"));

        let entry = parse_subvol_ogen_line(
            "ID 290 gen 374098 cgen 374097 top level 5 path my snapshot").unwrap();
        assert_eq!((entry.id, entry.ogen, entry.path.as_str()), (290, 374097, "my snapshot"));
    }

    #[test]
    fn subvol_ogen_rejects_a_line_without_cgen() {
        assert!(parse_subvol_ogen_line("ID 256 gen 362 top level 5 path root").is_none());
        assert!(parse_subvol_ogen_line("ID 256 gen 362 cgen x top level 5 path root").is_none());
    }

    fn stub_with(assignment: &str) -> bool {
        let stub = format!("{assignment}\n\
            search --no-floppy --root-dev-only --fs-uuid --set=dev 3f2a9c41\n\
            set prefix=($dev)/boot/grub2\n\
            configfile $prefix/grub.cfg\n");
        parse_esp_stub(&stub).unwrap().btrfs_relative
    }

    // GRUB's Btrfs driver tests only the value's first character for '1'
    // or 'y' (Fedora's grub2 2.12 patches, grub-core/fs/btrfs.c,
    // grub_btrfs_mount and find_path).
    #[test]
    fn esp_stub_btrfs_relative_follows_grub_value_rule() {
        assert!(stub_with("set btrfs_relative_path=\"yes\""));
        assert!(stub_with("set btrfs_relative_path=1"));
        assert!(stub_with("set btrfs_relative_path='y'"));
        assert!(stub_with("btrfs_relative_path=yes"));
        assert!(!stub_with("set btrfs_relative_path=\"no\""));
        assert!(!stub_with("set btrfs_relative_path=0"));
        assert!(!stub_with(""));
    }

    #[test]
    fn esp_stub_btrfs_relative_last_assignment_wins() {
        assert!(!stub_with("set btrfs_relative_path=yes\nset btrfs_relative_path=no"));
        assert!(stub_with("set btrfs_relative_path=no\nset btrfs_relative_path=1"));
    }

    // configfile hands over to grub.cfg, which GRUB runs with the
    // variables set so far; a later line in the stub does not run first.
    #[test]
    fn esp_stub_btrfs_relative_counts_only_before_configfile() {
        let stub = "search --no-floppy --root-dev-only --fs-uuid --set=dev 3f2a9c41\n\
            set prefix=($dev)/boot/grub2\n\
            configfile $prefix/grub.cfg\n\
            set btrfs_relative_path=y\n";
        assert!(!parse_esp_stub(stub).unwrap().btrfs_relative);

        let stub = format!("set btrfs_relative_path=y\n{stub}set btrfs_relative_path=n\n");
        assert!(parse_esp_stub(&stub).unwrap().btrfs_relative);
    }
}
