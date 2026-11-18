//! BOOTS predicate: evaluates whether the boot chain is valid by tracing
//! the boot chain from UEFI firmware through GRUB to the root filesystem.
//! Each check corresponds to a link in the chain:
//!   UEFI -> shim -> GRUB -> grub.cfg -> BLS entries -> kernel -> root mount -> fstab

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::grub::{self, BlsDir, Finding, StartingLookupDir, GrubContext, GrubContextError};
use crate::parse;
use crate::platform::FEDORA as P;
use crate::swap::RenameExchange;
use crate::tools;

type CheckResult = Result<(), Finding>;

/// Result of the BOOTS predicate evaluation.
pub enum BootStatus {
    Pass,
    Warn,
    Fail(Vec<String>),
    /// The check could not verify boot chain state (e.g., non-root
    /// invocation hits permission-denied on the ESP grub.cfg).
    /// Distinct from `Fail` because the boot chain may be fine; we
    /// simply did not have the access needed to evaluate it.
    Inaccessible { reason: String, hint: String },
}

/// A failure in any group fails the boot chain. Otherwise a group check
/// cannot verify leaves the boot chain unverified, since it may be valid.
fn evaluate_checks(checks: Vec<(&str, Vec<CheckResult>)>) -> BootStatus {
    let mut all_failures = Vec::new();
    let mut all_unverified = Vec::new();
    let mut warned = false;
    for (name, results) in &checks {
        if results.is_empty() {
            warned = true; // Check group handled its own WARN display
            continue;
        }
        let failures: Vec<&String> = results.iter()
            .filter_map(|r| match r { Err(Finding::Fails(f)) => Some(f), _ => None }).collect();
        let unverified: Vec<&String> = results.iter()
            .filter_map(|r| match r { Err(Finding::CannotVerify(f)) => Some(f), _ => None }).collect();
        if !failures.is_empty() {
            println!("  FAIL  {name}");
        } else if !unverified.is_empty() {
            println!("  CANNOT VERIFY  {name}");
        } else {
            println!("  PASS  {name}");
        }
        for f in &failures {
            println!("        {f}");
            all_failures.push(format!("{name}: {f}"));
        }
        for f in &unverified {
            println!("        {f}");
            all_unverified.push(format!("{name}: {f}"));
        }
    }
    if !all_failures.is_empty() {
        BootStatus::Fail(all_failures)
    } else if !all_unverified.is_empty() {
        BootStatus::Inaccessible {
            reason: all_unverified.join("; "),
            hint: "check could not read a file GRUB reads, so the boot chain may still be valid. \
                   Fix the error above and run check again.".into(),
        }
    } else if warned {
        BootStatus::Warn
    } else {
        BootStatus::Pass
    }
}

/// The status when check cannot build the GrubContext. A cause that needs
/// root is inaccessible, with the hint for that cause; command is the
/// atomic-rollback command to run as root. Any other cause is a failure,
/// described by describe.
fn context_unavailable(e: GrubContextError, command: &str, describe: impl FnOnce(String) -> String) -> BootStatus {
    match e {
        GrubContextError::EspUnreadable { path } => BootStatus::Inaccessible {
            reason: format!("permission denied reading {}", path.display()),
            hint: format!("The ESP grub.cfg is readable only by root on Fedora. \
                           Run: sudo atomic-rollback {command}"),
        },
        GrubContextError::MountNotPermitted => BootStatus::Inaccessible {
            reason: "mounting the Btrfs top-level subvolume requires root".into(),
            hint: format!("check mounts the Btrfs top-level subvolume read-only to read the files GRUB reads. \
                           Run: sudo atomic-rollback {command}"),
        },
        GrubContextError::CannotVerify(reason) => BootStatus::Inaccessible {
            reason,
            hint: "check cannot tell where GRUB looks the boot entries up, so the boot chain may still be valid.".into(),
        },
        GrubContextError::Other(msg) => BootStatus::Fail(vec![describe(msg)]),
    }
}

pub fn verify_bootable(root: &Path) -> BootStatus {
    let grub = match GrubContext::from_system(root) {
        Ok(g) => g,
        Err(e) => return context_unavailable(e, "check", |msg| format!(
            "Cannot determine how GRUB boots this system: {msg}. \
             Ensure {}/grub.cfg exists and the root filesystem is mounted.", P.esp_dir)),
    };
    print_starting_lookup_dirs(&grub);

    let blsdir = grub.blsdir();
    evaluate_checks(vec![
        ("EFI boot files", check_esp(root)),
        ("GRUB configuration", check_grub_config(root, &grub)),
        ("Kernel boot entry", check_bls_entries(&grub, &blsdir)),
        ("Root filesystem", check_root_mountable(root, &grub, &blsdir)),
        ("System mounts", check_fstab_mounts(root)),
    ])
}

/// Skips ESP checks (vfat, external to the btrfs snapshot) and
/// default subvol match (set-default comes after the exchange).
/// toplevel is where rollback mounted the top-level subvolume, and
/// exchange is the rename rollback makes once the snapshot passes.
pub fn verify_snapshot_bootable(toplevel: &Path, exchange: &RenameExchange) -> BootStatus {
    let grub = match GrubContext::for_snapshot(toplevel, exchange) {
        Ok(g) => g,
        Err(e) => return context_unavailable(e, "rollback", |msg| format!(
            "Cannot determine boot configuration: {msg}. \
             Ensure {}/grub.cfg exists.", P.esp_dir)),
    };
    print_starting_lookup_dirs(&grub);

    let snapshot = toplevel.join(exchange.snapshot.as_str());
    let blsdir = grub.blsdir();
    evaluate_checks(vec![
        ("GRUB configuration", check_grub_cfg(&grub, None)),
        ("Kernel boot entry", check_bls_entries(&grub, &blsdir)),
        ("Root filesystem", check_root_mountable(&snapshot, &grub, &blsdir)),
        ("System mounts", check_fstab_mounts(&snapshot)),
    ])
}

/// Names where GRUB starts its lookups, for each part of the boot where it
/// starts elsewhere.
fn print_starting_lookup_dirs(grub: &GrubContext) {
    let (at_configfile, at_blscfg) = (grub.at_configfile.describe(), grub.at_blscfg.describe());
    if at_configfile == at_blscfg {
        println!("  GRUB resolves paths from {at_blscfg}");
    } else {
        println!("  GRUB loads grub.cfg from {at_configfile}");
        println!("  GRUB reads the boot entries from {at_blscfg}, as grub.cfg leaves btrfs_relative_path");
    }
}

/// Gate: run verify_bootable, exit on failure.
/// swap_artifact: if this gate follows a RENAME_EXCHANGE, the path where
/// the old file now lives (e.g., "/boot/grub2/grub.cfg.new"). On failure,
/// the user is told the swap completed and where the old file is.
pub fn gate(step: &str, root: &Path, swap_artifact: Option<&str>) {
    println!();
    match verify_bootable(root) {
        BootStatus::Pass => println!("  GATE {step}: PASS\n"),
        BootStatus::Warn => println!("  GATE {step}: PASS\n"),
        BootStatus::Fail(failures) => {
            println!("\n  GATE {step}: FAIL");
            if let Some(old) = swap_artifact {
                eprintln!("    The swap completed. Old file preserved at {old}.");
            }
            for f in &failures {
                eprintln!("    {f}");
            }
            std::process::exit(1);
        }
        BootStatus::Inaccessible { reason, hint } => {
            // Migration runs as root; reaching this branch means something
            // unexpected prevented verification. Fail safe (don't proceed).
            println!("\n  GATE {step}: FAIL");
            if let Some(old) = swap_artifact {
                eprintln!("    The swap completed. Old file preserved at {old}.");
            }
            eprintln!("    Cannot verify boot chain: {reason}");
            eprintln!("    {hint}");
            std::process::exit(1);
        }
    }
}

// --- EFI boot files ---

fn check_esp(root: &Path) -> Vec<CheckResult> {
    let efi_dir = root.join(&P.esp_dir[1..]);
    let mut results = Vec::new();

    let s = P.efi_suffix;
    for name in [format!("shim{s}.efi"), format!("grub{s}.efi")] {
        let path = efi_dir.join(&name);
        results.push(check_file_exists_nonempty(&path).map_err(|_|
            format!("{name} is missing from the EFI partition. \
                     The system cannot boot without it. \
                     Reinstall the grub2-efi package: sudo dnf reinstall grub2-efi-{s}").into()
        ));
    }

    let grub_cfg = efi_dir.join("grub.cfg");
    results.push(check_file_exists_nonempty(&grub_cfg).map_err(|_|
        format!("EFI grub.cfg is missing at {}. \
                 GRUB will drop to a rescue shell on next boot. \
                 Reinstall: sudo dnf reinstall grub2-efi-{s}", grub_cfg.display()).into()
    ));
    results.push(check_file_contains(&grub_cfg, "--fs-uuid",
        "EFI grub.cfg does not contain a filesystem search directive. \
         GRUB will not find the boot partition. \
         Regenerate with: sudo grub2-switch-to-blscfg"));
    results.push(check_file_contains(&grub_cfg, "configfile",
        "EFI grub.cfg does not load the main GRUB configuration. \
         GRUB will drop to a rescue shell. \
         Regenerate with: sudo grub2-switch-to-blscfg"));

    results
}

// --- GRUB configuration ---

fn check_grub_config(root: &Path, grub: &GrubContext) -> Vec<CheckResult> {
    let regenerate = format!("Regenerate with: sudo grub2-mkconfig -o {}/grub.cfg", P.grub_dir);
    let mut results = check_grub_cfg(grub, Some(&regenerate));

    let default_subvol = [&grub.at_configfile, &grub.at_blscfg].into_iter().find_map(|start| match start {
        StartingLookupDir::BtrfsDefaultSubvol(default_subvol) => Some(default_subvol),
        _ => None,
    });
    if let Some(default_subvol) = default_subvol {
        results.push(check_default_subvol_matches_root(&default_subvol.to_string_lossy(), root));
    }

    results
}

/// The grub.cfg GRUB loads, which must list the boot entries with blscfg.
/// The ESP stub runs configfile $prefix/grub.cfg, and GRUB resolves the
/// prefix like every other path; in the snapshot check, from where it will
/// start after the exchange. remedy, when given, says how to regenerate
/// the file.
fn check_grub_cfg(grub: &GrubContext, remedy: Option<&str>) -> Vec<CheckResult> {
    let remedy = remedy.map(|r| format!(" {r}")).unwrap_or_default();
    let grub_path = grub.grub_dir_file("grub.cfg");
    let content = match read_grub_file(&grub.at_configfile, &grub_path) {
        Ok(content) => content,
        Err(finding) => return vec![Err(finding.map_fails(|fact| format!(
            "GRUB loads its configuration from '{grub_path}': {fact}. \
             GRUB will drop to a rescue shell on next boot.{remedy}")))],
    };
    vec![
        if content.is_empty() {
            Err(format!("GRUB loads its configuration from '{grub_path}', which is empty. \
                         GRUB will drop to a rescue shell on next boot.{remedy}").into())
        } else {
            Ok(())
        },
        match grub::runs_blscfg(&content) {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!("GRUB configuration does not use Boot Loader Specification entries: \
                                      '{grub_path}' runs no blscfg command. \
                                      Kernel boot entries will not appear in the GRUB menu.{remedy}").into()),
            Err(why) => Err(Finding::CannotVerify(why)),
        },
    ]
}

/// The content of the file GRUB opens at grub_path from start. A Linux
/// error reading it says nothing about GRUB, so check cannot verify past it.
fn read_grub_file(start: &StartingLookupDir, grub_path: &str) -> Result<String, Finding> {
    let path = start.find_file(grub_path)?;
    fs::read_to_string(path).map_err(|e| Finding::CannotVerify(format!("cannot verify '{grub_path}': {e}")))
}

fn check_default_subvol_matches_root(mount_point: &str, root: &Path) -> CheckResult {
    let default_id = tools::btrfs_subvol_get_default(mount_point)?.id();

    let fstab_content = fs::read_to_string(root.join("etc/fstab"))
        .map_err(|e| format!("Cannot read /etc/fstab: {e}"))?;
    let root_subvol_name = tools::root_subvol_name(&fstab_content)
        .map_err(|e| format!("{e}. The fstab entry for / must include subvol=<name>."))?;

    let root_subvol_id = tools::btrfs_subvol_id_by_name(mount_point, &root_subvol_name)?;

    default_subvol_is_root(default_id, &root_subvol_name, root_subvol_id)
}

/// GRUB, starting at the default subvolume default_id, and Linux, which
/// mounts root_subvol_name (ID root_subvol_id) as /, see the same root
/// filesystem only when they are the same subvolume.
fn default_subvol_is_root(default_id: u64, root_subvol_name: &tools::SubvolName, root_subvol_id: u64) -> CheckResult {
    if default_id == root_subvol_id {
        Ok(())
    } else {
        Err(format!(
            "GRUB and Linux see different root filesystems. \
             GRUB resolves paths from subvolume ID {default_id}, \
             but the subvolume '{root_subvol_name}' (mounted as /) has ID {root_subvol_id}. \
             The system will not boot correctly. \
             Fix: sudo btrfs subvolume set-default {root_subvol_id} /"
        ).into())
    }
}

// --- Kernel boot entry ---

/// blsdir is the directory blscfg reads boot entries from, as
/// GrubContext::blsdir finds it.
fn check_bls_entries(grub: &GrubContext, blsdir: &Result<BlsDir, Finding>) -> Vec<CheckResult> {
    let blsdir = match blsdir {
        Ok(dir) => dir,
        Err(finding) => return vec![Err(finding.clone().map_fails(|e| format!("{e}. GRUB will show an empty menu.")))],
    };

    let confs = match bls_entry_paths(blsdir) {
        Ok(confs) => confs,
        Err(finding) => return vec![Err(finding)],
    };

    // Validate ALL entries, not just until the first valid one
    let mut valid = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    for conf in &confs {
        let content = match read_grub_file(&grub.at_blscfg, conf) {
            Ok(content) => content,
            // blscfg skips a file it cannot open (Fedora's grub2 2.12
            // patches, grub-core/commands/blscfg.c, read_entry).
            Err(Finding::Fails(_)) => continue,
            Err(Finding::CannotVerify(e)) => {
                unverified.push(e);
                continue;
            }
        };
        match validate_bls_entry(grub, conf, &content) {
            Ok(()) => valid += 1,
            Err(Finding::Fails(e)) => failures.push(e),
            Err(Finding::CannotVerify(e)) => unverified.push(e),
        }
    }

    let total = valid + failures.len() + unverified.len();

    if total == 0 {
        return vec![Err(format!(
            "No boot entries found in '{}'. \
             GRUB will show an empty menu with no kernels to boot. \
             Reinstall the kernel: sudo dnf reinstall kernel-core",
            blsdir.grub_path).into())];
    }

    if valid == total {
        return vec![Ok(())];
    }

    if valid > 0 {
        // System boots but some entries are broken or unverified. WARN,
        // not PASS. Print here; return empty so evaluate_checks skips this
        // group.
        println!("  WARN  Kernel boot entry ({valid} of {total} valid)");
        for f in failures.iter().chain(&unverified) {
            println!("        {f}");
        }
        return vec![];
    }

    // No entry is valid, but one check cannot verify may be: whether GRUB
    // boots is unknown, and the broken entries are listed with it.
    if !unverified.is_empty() {
        return unverified.into_iter().chain(failures).map(|e| Err(Finding::CannotVerify(e))).collect();
    }

    let mut results: Vec<CheckResult> = failures.into_iter().map(|e| Err(Finding::Fails(e))).collect();
    results.push(Err(
        "No boot entry has a valid kernel, initramfs, and root parameter. \
         The system cannot boot. \
         Rebuild the boot entry: sudo kernel-install add $(uname -r) /lib/modules/$(uname -r)/vmlinuz".to_string().into()));
    results
}

/// The GRUB paths of the files in blsdir whose names blscfg reads as boot
/// entries.
fn bls_entry_paths(blsdir: &BlsDir) -> Result<Vec<String>, Finding> {
    let unverified = |e: std::io::Error| Finding::CannotVerify(format!(
        "cannot verify the boot entries in '{}': {e}", blsdir.grub_path));
    let mut confs = Vec::new();
    for entry in fs::read_dir(&blsdir.linux).map_err(unverified)? {
        let name = entry.map_err(unverified)?.file_name();
        if !is_bls_entry_name(name.as_bytes()) {
            continue;
        }
        let name = name.into_string().map_err(|name| Finding::CannotVerify(format!(
            "cannot verify the boot entry {name:?} in '{}': its name is not UTF-8, which check does not look up",
            blsdir.grub_path)))?;
        confs.push(blsdir.entry(&name));
    }
    Ok(confs)
}

/// Whether blscfg reads the file of this name in the boot entry directory:
/// it skips a name that starts with '.', has 5 bytes or fewer, or does not
/// end in ".conf" (Fedora's grub2 2.12 patches,
/// grub-core/commands/blscfg.c, read_entry).
fn is_bls_entry_name(name: &[u8]) -> bool {
    const BLS_ENTRY_SUFFIX: &[u8] = b".conf";
    name.first() != Some(&b'.') && name.len() > BLS_ENTRY_SUFFIX.len() && name.ends_with(BLS_ENTRY_SUFFIX)
}

// BLS fields may contain GRUB variables after the file path:
//   initrd /initramfs-6.19.9.img $tuned_initrd
// Only the first token is a file path. The rest is GRUB's concern.
// conf is the entry's GRUB path, and content what GRUB reads there.
fn validate_bls_entry(grub: &GrubContext, conf: &str, content: &str) -> CheckResult {
    let linux = parse::bls_field(content, "linux")
        .ok_or_else(|| format!(
            "Boot entry '{conf}' has no 'linux' field. \
             GRUB does not know which kernel to load."))?;
    let options = parse::bls_field(content, "options")
        .ok_or_else(|| format!(
            "Boot entry '{conf}' has no 'options' field. \
             The kernel will not know which root filesystem to mount."))?;

    grub.at_blscfg.find_file(linux).map_err(|e| Finding::from(e).map_fails(|fact| format!(
        "GRUB cannot find the kernel ({fact}). \
         The system will not boot with this entry.")))?;

    // initrd may appear on multiple lines (BLS spec). Each value may contain
    // GRUB variables ($tuned_initrd) which are resolved at boot, not checkable here.
    // GRUB stores everything after the first delimiter as the value (blsuki.c:316).
    let initrd_values = parse::bls_field_all(content, "initrd");
    if initrd_values.is_empty() {
        return Err(format!(
            "Boot entry '{conf}' has no 'initrd' field. \
             The kernel will panic without an initial ramdisk.").into());
    }
    for initrd_val in &initrd_values {
        for path in initrd_val.split_whitespace() {
            if path.starts_with('$') { continue; } // GRUB variable
            grub.at_blscfg.find_file(path).map_err(|e| Finding::from(e).map_fails(|fact| format!(
                "GRUB cannot find the initial ramdisk ({fact}). \
                 The kernel will panic during boot.")))?;
        }
    }

    // root= accepts UUID=, LABEL= (initramfs-resolved), PARTUUID=, PARTLABEL=,
    // /dev/ paths (kernel early_lookup_bdev, block/early-lookup.c:244).
    if !options.contains("root=") {
        return Err(format!(
            "Boot entry '{conf}' does not specify a root filesystem (missing root= parameter). \
             The kernel will not know what to mount.").into());
    }

    Ok(())
}

// --- Root filesystem ---

fn check_root_mountable(root: &Path, grub: &GrubContext, blsdir: &Result<BlsDir, Finding>) -> Vec<CheckResult> {
    let mut results = Vec::new();

    let root_uuid = match extract_root_uuid(grub, blsdir) {
        Ok(Some(uuid)) => uuid,
        Ok(None) => {
            results.push(Err(
                "Cannot determine root filesystem UUID from boot entries. \
                 No boot entry specifies root=UUID=. \
                 The system may not boot.".to_string().into()));
            return results;
        }
        Err(finding) => {
            results.push(Err(finding));
            return results;
        }
    };

    results.push(check_blkid_uuid_fstype(&root_uuid, tools::FsType::Btrfs).map_err(|e| e.map(|e| format!(
        "Root filesystem UUID {} is not a Btrfs partition: {e}. \
         This tool requires Btrfs as the root filesystem.", root_uuid.as_str()))));

    let fstab_content = match fs::read_to_string(root.join("etc/fstab")) {
        Ok(c) => c,
        Err(e) => {
            results.push(Err(format!(
                "Cannot read /etc/fstab to determine root subvolume: {e}. \
                 The system may not boot.").into()));
            return results;
        }
    };

    let root_subvol_name = match tools::root_subvol_name(&fstab_content) {
        Ok(name) => name,
        Err(e) => {
            results.push(Err(format!(
                "{e}. The fstab entry for / must include subvol=<name>.").into()));
            return results;
        }
    };

    let root_device = root_uuid.clone().into_device_spec();
    results.push(check_btrfs_subvol_exists(&root_device, &root_subvol_name).map_err(|e| e.map(|e| format!(
        "Btrfs subvolume '{root_subvol_name}' not found: {e}. \
         The kernel expects to mount subvol={root_subvol_name} as /. \
         Without it, the system drops to an emergency shell."))));

    results.push(check_file_exists_nonempty(&root.join(&P.systemd_path[1..])).map_err(|_|
        format!("systemd (PID 1) is missing at {}. \
         The kernel will panic after mounting root. \
         Reinstall: sudo dnf reinstall systemd", P.systemd_path).into()));

    results
}

// --- System mounts ---

fn check_fstab_mounts(root: &Path) -> Vec<CheckResult> {
    let content = match fs::read_to_string(root.join("etc/fstab")) {
        Ok(c) => c,
        Err(e) => return vec![Err(format!(
            "Cannot read /etc/fstab: {e}. \
             systemd will not mount any filesystems.").into())],
    };

    let lines = tools::parse_fstab(&content);
    let mut results = Vec::new();
    for e in tools::fstab_entries(&lines) {
        if e.fs_mntops.contains("nofail") || e.fs_vfstype == tools::FsType::Swap
           || e.fs_file == "none" || e.fs_file == "swap" { continue; }

        results.push(check_fstab_entry(&e.fs_spec, &e.fs_file, &e.fs_vfstype, &e.fs_mntops));
    }

    results
}

fn check_fstab_entry(device: &tools::DeviceSpec, mount_point: &str, fstype: &tools::FsType, options: &str) -> CheckResult {
    tools::resolve_fstab_device(device)
        .map_err(|_| format!(
            "Mount {mount_point}: device {device} does not resolve. \
             systemd will fail to mount it and the system may hang at boot. \
             Check /etc/fstab or add 'nofail' to the mount options."))?;

    if *fstype == tools::FsType::Btrfs {
        if let Some(subvol) = parse::extract_mount_option(options, "subvol") {
            return check_btrfs_subvol_exists(device, &tools::SubvolName::new(subvol.to_string()))
                .map_err(|_| format!(
                    "Mount {mount_point}: Btrfs subvolume '{subvol}' does not exist. \
                     systemd will fail to mount it and the system may hang at boot. \
                     Create the subvolume or remove the fstab entry.").into());
        }
    }

    Ok(())
}

// --- Leaf helpers ---

fn check_file_exists_nonempty(path: &Path) -> CheckResult {
    match fs::metadata(path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("{} exists but is empty", path.display()).into()),
        Err(_) => Err(format!("{} does not exist", path.display()).into()),
    }
}

fn check_file_contains(path: &Path, needle: &str, msg: &str) -> CheckResult {
    match fs::read_to_string(path) {
        Ok(content) if content.contains(needle) => Ok(()),
        Ok(_) => Err(msg.to_string().into()),
        Err(e) => Err(format!("Cannot read {}: {e}", path.display()).into()),
    }
}

fn check_blkid_uuid_fstype(uuid: &tools::BareUuid, expected: tools::FsType) -> CheckResult {
    let fstype = tools::blkid_fstype(&tools::blkid_device_for_uuid(uuid)?)?;
    if fstype == expected { Ok(()) } else {
        Err(format!("UUID={} has unexpected filesystem type", uuid.as_str()).into())
    }
}

fn check_btrfs_subvol_exists(device_spec: &tools::DeviceSpec, name: &tools::SubvolName) -> CheckResult {
    let mount = tools::get_mount_point(device_spec)?;
    let entries = tools::btrfs_subvol_list(mount.path())?;
    if entries.iter().any(|e| e.path == name.as_str()) {
        Ok(())
    } else {
        Err(format!("subvolume '{name}' not found on {device_spec}").into())
    }
}

pub fn print_rollback_scope(fstab: &str) {
    let lines = tools::parse_fstab(fstab);
    let entries = tools::fstab_entries(&lines);

    let protected: Vec<&str> = entries.iter()
        .filter(|e| e.fs_file != "/")
        .filter(|e| parse::extract_mount_option(&e.fs_mntops, "subvol").is_some())
        .map(|e| e.fs_file.as_str())
        .collect();

    println!("  Rollback scope:\n");

    if !protected.is_empty() {
        println!("  SAFE  Separate subvolumes (not affected by rollback):");
        for p in &protected {
            println!("        {p}");
        }
        println!();
    }

    let at_risk: Vec<String> = match fs::read_dir("/") {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|ft| ft.is_dir()))
            .map(|e| format!("/{}", e.file_name().to_string_lossy()))
            .filter(|dir| !tools::is_mountpoint(Path::new(dir)))
            .filter(|dir| fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()))
            .collect(),
        Err(_) => vec![],
    };

    if !at_risk.is_empty() {
        println!("  RISK  Inside root subvolume (will revert on rollback):");
        for r in &at_risk {
            println!("        {r}");
        }
        println!();
    }
}

/// The root= UUID of the first boot entry GRUB reads.
fn extract_root_uuid(grub: &GrubContext, blsdir: &Result<BlsDir, Finding>) -> Result<Option<tools::BareUuid>, Finding> {
    let blsdir = match blsdir {
        Ok(dir) => dir,
        Err(Finding::Fails(_)) => return Ok(None),
        Err(unverified) => return Err(unverified.clone()),
    };
    for conf in bls_entry_paths(blsdir)? {
        let content = match read_grub_file(&grub.at_blscfg, &conf) {
            Ok(content) => content,
            // blscfg skips a file it cannot open.
            Err(Finding::Fails(_)) => continue,
            Err(unverified) => return Err(unverified),
        };
        if let Some(options) = parse::bls_field(&content, "options") {
            return Ok(parse::extract_root_uuid_from_options(options));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn hint(status: BootStatus) -> String {
        match status {
            BootStatus::Inaccessible { hint, .. } => hint,
            _ => panic!("a cause that needs root is reported as inaccessible"),
        }
    }

    // A non-root check on a system whose /boot is ext4 stops at the ESP
    // grub.cfg; its hint names only that file.
    #[test]
    fn each_cause_that_needs_root_has_its_own_hint() {
        let esp = hint(context_unavailable(
            GrubContextError::EspUnreadable { path: PathBuf::from("/boot/efi/EFI/fedora/grub.cfg") },
            "check", |msg| msg));
        assert!(esp.contains("ESP grub.cfg") && !esp.contains("mount"), "{esp}");

        let mount = hint(context_unavailable(GrubContextError::MountNotPermitted, "check", |msg| msg));
        assert!(mount.contains("mounts the Btrfs top-level subvolume") && !mount.contains("ESP"), "{mount}");
    }

    #[test]
    fn check_esp_uses_arch_correct_filenames() {
        let dir = std::env::temp_dir().join("atomic-rollback-test-esp");
        let _ = fs::remove_dir_all(&dir);
        let efi_dir = dir.join(&P.esp_dir[1..]);
        fs::create_dir_all(&efi_dir).unwrap();

        fs::write(efi_dir.join(format!("shim{}.efi", P.efi_suffix)), b"shim").unwrap();
        fs::write(efi_dir.join(format!("grub{}.efi", P.efi_suffix)), b"grub").unwrap();

        fs::write(
            efi_dir.join("grub.cfg"),
            "search --no-floppy --fs-uuid --set=dev abc-123\nconfigfile $prefix/grub.cfg\n",
        ).unwrap();

        let results = check_esp(&dir);
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "check {i} failed: {:?}", r.as_ref().err());
        }

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn root_subvol_name_reads_at_sign_layout() {
        let fstab = "\
UUID=abc / btrfs subvol=@,compress=zstd:1 0 0
UUID=abc /home btrfs subvol=@home,compress=zstd:1 0 0
UUID=abc /var btrfs subvol=@var 0 0
UUID=abc /opt btrfs subvol=@opt 0 0";
        let name = tools::root_subvol_name(fstab).unwrap();
        assert_eq!(name.as_str(), "@");
    }

    #[test]
    fn root_subvol_name_reads_fedora_default() {
        let fstab = "UUID=abc / btrfs subvol=root,compress=zstd:1 0 0";
        let name = tools::root_subvol_name(fstab).unwrap();
        assert_eq!(name.as_str(), "root");
    }

    #[test]
    fn root_subvol_name_errors_without_subvol_option() {
        let fstab = "UUID=abc / btrfs defaults 0 0";
        assert!(tools::root_subvol_name(fstab).is_err());
    }

    // --- GRUB path resolution through the checks ---
    //
    // Each scratch directory stands in for the directory GRUB starts from
    // (the mounted top-level subvolume, or the boot partition's root).

    const KVER: &str = "6.19.9-200.fc45.x86_64";

    // Where 10_linux points blsdir on Btrfs: grub2-mkrelpath of
    // /boot/loader/entries, relative to the top-level subvolume.
    const BLSDIR_TOP_LEVEL: &str = "blsdir=/root/boot/loader/entries\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("atomic-rollback-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn put(path: &Path, content: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn grubenv(vars: &str) -> String {
        format!("# GRUB Environment Block\n{vars}{}", "#".repeat(256))
    }

    fn bls_entry(linux: &str, initrds: &[&str]) -> String {
        let mut entry = format!("title Fedora Linux ({KVER})\nversion {KVER}\nlinux {linux}\n");
        for initrd in initrds {
            entry.push_str(&format!("initrd {initrd}\n"));
        }
        entry.push_str("options root=UUID=3f2a9c41 ro rootflags=subvol=root\n");
        entry
    }

    /// Paths Fedora's 20-grub.install writes on Btrfs: from the top level.
    fn entry_from_top_level() -> String {
        bls_entry(&format!("/root/boot/vmlinuz-{KVER}"), &[&format!("/root/boot/initramfs-{KVER}.img")])
    }

    /// Paths the kernel hook writes after migrate: from the root subvolume.
    fn entry_from_root_subvol() -> String {
        bls_entry(&format!("/vmlinuz-{KVER}"), &[&format!("/initramfs-{KVER}.img")])
    }

    /// Lays out the subvolume <top>/<subvol> as migrate leaves the root
    /// subvolume: kernel and initramfs in boot/, symlinks to them at the
    /// subvolume's root, grub.cfg and grubenv in boot/grub2, and one BLS
    /// entry in boot/loader/entries.
    fn install_subvol(top: &Path, subvol: &str, grubenv_vars: &str, entry: &str) {
        let dir = top.join(subvol);
        put(&dir.join(format!("boot/vmlinuz-{KVER}")), "kernel");
        put(&dir.join(format!("boot/initramfs-{KVER}.img")), "initramfs");
        std::os::unix::fs::symlink(format!("boot/vmlinuz-{KVER}"), dir.join(format!("vmlinuz-{KVER}"))).unwrap();
        std::os::unix::fs::symlink(format!("boot/initramfs-{KVER}.img"), dir.join(format!("initramfs-{KVER}.img"))).unwrap();
        put(&dir.join("boot/grub2/grub.cfg"), "insmod blscfg\nblscfg\n");
        put(&dir.join("boot/grub2/grubenv"), &grubenv(grubenv_vars));
        put(&dir.join(format!("boot/loader/entries/{KVER}.conf")), entry);
    }

    /// An ESP stub as gen_grub_cfgstub writes it for prefix, with
    /// btrfs_relative_path set as migrate sets it when btrfs_relative.
    fn esp_stub(btrfs_relative: bool, prefix: &str) -> String {
        let relative = if btrfs_relative { "set btrfs_relative_path=\"yes\"\n" } else { "" };
        format!("{relative}search --no-floppy --root-dev-only --fs-uuid --set=dev 3f2a9c41\n\
                 set prefix=($dev){prefix}\nexport $prefix\nconfigfile $prefix/grub.cfg\n")
    }

    /// GRUB's view, built as from_system builds it, of a Btrfs filesystem
    /// whose top level is visible at top and whose default subvolume is
    /// root, under the ESP stub stub.
    fn context_from_stub(top: &Path, stub: &str) -> Result<GrubContext, GrubContextError> {
        context_with_grub_env(top, stub, None)
    }

    /// The same, with the GRUB_ENV EFI variable holding grub_env.
    fn context_with_grub_env(top: &Path, stub: &str, grub_env: Option<&[u8]>) -> Result<GrubContext, GrubContextError> {
        let btrfs = tools::FsType::Btrfs;
        GrubContext::build(stub, tools::parse_esp_stub(stub).unwrap(), &btrfs, &top.join("partition"), grub_env,
            |btrfs_relative| StartingLookupDir::select(&btrfs, btrfs_relative, top.to_path_buf(), || Ok("root".into())),
            None)
    }

    fn btrfs_context(top: &Path, btrfs_relative: bool, prefix: &str) -> GrubContext {
        context_from_stub(top, &esp_stub(btrfs_relative, prefix)).unwrap()
    }

    /// GRUB's view, built as for_snapshot builds it, of the filesystem
    /// root, of type fstype, once rollback exchanges the root subvolume and
    /// snapshot, under the ESP stub for prefix.
    fn after_rollback_context(fstype: tools::FsType, root: &Path, snapshot: &str, prefix: &str) -> GrubContext {
        let exchange = RenameExchange {
            root: tools::SubvolName::new("root".into()),
            snapshot: tools::SubvolName::new(snapshot.into()),
        };
        let stub = esp_stub(false, prefix);
        GrubContext::build(&stub, tools::parse_esp_stub(&stub).unwrap(), &fstype, &root.join("partition"), None,
            |btrfs_relative| Ok(StartingLookupDir::after_rollback(&fstype, btrfs_relative, root.to_path_buf(), &exchange)),
            None).unwrap()
    }

    fn snapshot_context(top: &Path, snapshot: &str) -> GrubContext {
        after_rollback_context(tools::FsType::Btrfs, top, snapshot, "/root/boot/grub2")
    }

    fn bls_entries(grub: &GrubContext) -> Vec<CheckResult> {
        check_bls_entries(grub, &grub.blsdir())
    }

    fn validate(grub: &GrubContext, conf: &str) -> CheckResult {
        validate_bls_entry(grub, conf, &read_grub_file(&grub.at_blscfg, conf)?)
    }

    fn passes(results: &[CheckResult]) -> bool {
        !results.is_empty() && results.iter().all(|r| r.is_ok())
    }

    fn fails_with(results: &[CheckResult], needle: &str) -> bool {
        !results.is_empty()
            && results.iter().all(|r| matches!(r, Err(Finding::Fails(_))))
            && results.iter().any(|r| matches!(r, Err(Finding::Fails(e)) if e.contains(needle)))
    }

    fn refuses(results: &[CheckResult], needle: &str) -> bool {
        results.iter().any(|r| matches!(r, Err(Finding::Fails(e)) if e.contains(needle)))
    }

    /// A system set up without migrate: /boot is ext4, outside the root
    /// subvolume, and holds grub2/, loader/entries/ and the kernels. The
    /// context is the snapshot check's, which reads that live /boot.
    fn separate_boot(boot: &Path) -> GrubContext {
        put(&boot.join("grub2/grub.cfg"), "insmod blscfg\nblscfg\n");
        put(&boot.join("grub2/grubenv"), &grubenv(""));
        put(&boot.join(format!("vmlinuz-{KVER}")), "kernel");
        put(&boot.join(format!("initramfs-{KVER}.img")), "initramfs");
        put(&boot.join(format!("loader/entries/{KVER}.conf")), &entry_from_root_subvol());
        after_rollback_context(tools::FsType::Ext4, boot, "snap1", "/grub2")
    }

    #[test]
    fn top_level_accepts_paths_from_the_top_level() {
        let top = scratch("grub-top-level-accepts");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        assert!(passes(&check_grub_config(&top, &grub)));
        assert!(passes(&bls_entries(&grub)));
        fs::remove_dir_all(&top).unwrap();
    }

    // The Fedora 44 failure: Fedora's ESP stub, which does not set
    // btrfs_relative_path, over a migrated system whose entries name
    // /vmlinuz-<ver>. Linux finds that file through the symlink in the root
    // subvolume; GRUB looks in the top level, which has no such entry.
    #[test]
    fn top_level_refuses_paths_from_the_root_subvolume() {
        let top = scratch("grub-top-level-refuses");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_root_subvol());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        let results = bls_entries(&grub);
        assert!(fails_with(&results, &format!("`/vmlinuz-{KVER}'")), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    // The same system under the stub migrate writes: btrfs_relative_path
    // set, so GRUB starts at the default subvolume. Its grubenv blsdir is
    // the top-level form, which does not resolve there; blscfg falls back
    // to /boot/loader/entries.
    #[test]
    fn default_subvol_accepts_paths_from_the_default_subvolume() {
        let top = scratch("grub-default-subvol-accepts");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_root_subvol());
        let grub = btrfs_context(&top, true, "/boot/grub2");

        assert!(passes(&bls_entries(&grub)));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn default_subvol_refuses_paths_from_the_top_level() {
        let top = scratch("grub-default-subvol-refuses");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, true, "/boot/grub2");

        let results = bls_entries(&grub);
        assert!(fails_with(&results, &format!("`/root/boot/vmlinuz-{KVER}'")), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    // migrate's prefix /boot/grub2 is relative to the root subvolume.
    // Without btrfs_relative_path, GRUB looks for it in the top level.
    #[test]
    fn top_level_refuses_prefix_from_the_root_subvolume() {
        let top = scratch("grub-top-level-prefix");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/boot/grub2");

        let results = check_grub_config(&top, &grub);
        assert!(fails_with(&results, "'/boot/grub2/grub.cfg'"), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    // migrate recreates grubenv without blsdir. From the top level, GRUB
    // then finds neither /loader/entries nor /boot/loader/entries.
    #[test]
    fn top_level_without_blsdir_finds_no_entries() {
        let top = scratch("grub-top-level-no-blsdir");
        install_subvol(&top, "root", "", &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        let results = bls_entries(&grub);
        assert!(fails_with(&results, "`/boot/loader/entries/'"), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn default_subvol_without_blsdir_uses_the_fallback_directory() {
        let top = scratch("grub-default-subvol-no-blsdir");
        install_subvol(&top, "root", "", &entry_from_root_subvol());
        let grub = btrfs_context(&top, true, "/boot/grub2");

        assert!(passes(&bls_entries(&grub)));
        fs::remove_dir_all(&top).unwrap();
    }

    // Stock Fedora and setup-only systems: the stub names the ext4 /boot,
    // whose root holds grub2/, loader/entries/ and the kernels.
    #[test]
    fn filesystem_root_accepts_boot_partition_layout() {
        let boot = scratch("grub-filesystem-root");
        put(&boot.join("grub2/grub.cfg"), "insmod blscfg\nblscfg\n");
        put(&boot.join("grub2/grubenv"), &grubenv(""));
        put(&boot.join(format!("vmlinuz-{KVER}")), "kernel");
        put(&boot.join(format!("initramfs-{KVER}.img")), "initramfs");
        put(&boot.join(format!("loader/entries/{KVER}.conf")), &entry_from_root_subvol());
        // Fedora cloud images set btrfs_relative_path on an ext4 /boot.
        let stub = esp_stub(true, "/grub2");
        let ext4 = tools::FsType::Ext4;
        let grub = GrubContext::build(&stub, tools::parse_esp_stub(&stub).unwrap(), &ext4, &boot.join("partition"), None,
            |btrfs_relative| StartingLookupDir::select(&ext4, btrfs_relative, boot.clone(),
                || panic!("no default subvolume off Btrfs")),
            None).unwrap();

        assert!(passes(&check_grub_config(&boot, &grub)));
        assert!(passes(&bls_entries(&grub)));
        fs::remove_dir_all(&boot).unwrap();
    }

    // Rollback renames the snapshot to the root subvolume's name, so a
    // path through /root/ reaches the snapshot after the exchange.
    #[test]
    fn snapshot_check_follows_root_paths_into_the_snapshot() {
        let top = scratch("grub-snapshot-exchange");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        install_subvol(&top, "snap1", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = snapshot_context(&top, "snap1");

        assert!(passes(&bls_entries(&grub)));

        // The live root still has the kernel; the snapshot does not.
        fs::remove_file(top.join(format!("snap1/boot/vmlinuz-{KVER}"))).unwrap();
        let results = bls_entries(&grub);
        assert!(fails_with(&results, &format!("`/root/boot/vmlinuz-{KVER}' not found")), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn snapshot_check_reads_the_snapshot_entries() {
        let top = scratch("grub-snapshot-entries");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        install_subvol(&top, "snap1", BLSDIR_TOP_LEVEL, &entry_from_root_subvol());
        let grub = snapshot_context(&top, "snap1");

        // The snapshot's entries name /vmlinuz-<ver>, which the top level
        // does not hold, although the live root's entries resolve.
        let results = bls_entries(&grub);
        assert!(fails_with(&results, &format!("`/vmlinuz-{KVER}'")), "{:?}", results);
        fs::remove_dir_all(&top).unwrap();
    }

    // A setup-only system: /boot is ext4, outside the root subvolume, so a
    // snapshot holds an empty boot/ directory. After rollback GRUB still
    // reads the live ext4 /boot, so the GRUB side of the snapshot check
    // resolves there, and the root= UUID comes from those entries.
    #[test]
    fn setup_only_snapshot_check_reads_the_live_boot_partition() {
        let scratch_dir = scratch("grub-setup-only-snapshot");
        let boot = scratch_dir.join("boot");
        let grub = separate_boot(&boot);
        let snapshot = scratch_dir.join("top/snap1");
        fs::create_dir_all(snapshot.join("boot")).unwrap();
        put(&snapshot.join("etc/fstab"), "UUID=3f2a9c41 / btrfs subvol=root 0 0\n");

        assert!(passes(&check_grub_cfg(&grub, None)), "{:?}", check_grub_cfg(&grub, None));
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        assert_eq!(extract_root_uuid(&grub, &grub.blsdir()).unwrap().map(|u| u.as_str().to_string()), Some("3f2a9c41".into()));
        fs::remove_dir_all(&scratch_dir).unwrap();
    }

    // --- the files blscfg reads ---

    /// Adds files blscfg does not read as entries to dir: a name starting
    /// with '.', a name not ending in ".conf", and two it cannot open.
    fn put_files_blscfg_skips(dir: &Path) {
        put(&dir.join(".hidden.conf"), "title not read\n");
        put(&dir.join("notes.txt"), "title not read\n");
        std::os::unix::fs::symlink("gone.conf", dir.join("dangling.conf")).unwrap();
        fs::create_dir_all(dir.join("dir.conf")).unwrap();
    }

    // blscfg reads only a file whose name does not start with '.', is longer
    // than 5 bytes and ends in ".conf", and skips one it cannot open
    // (Fedora's grub2 2.12 patches, grub-core/commands/blscfg.c,
    // read_entry). None of them is a broken entry.
    #[test]
    fn files_blscfg_does_not_read_are_not_boot_entries() {
        let top = scratch("bls-entry-names");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put_files_blscfg_skips(&top.join("root/boot/loader/entries"));
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        let results = bls_entries(&grub);
        assert!(passes(&results), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn a_directory_of_files_blscfg_does_not_read_has_no_boot_entries() {
        let top = scratch("bls-entry-names-none");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let entries = top.join("root/boot/loader/entries");
        fs::remove_file(entries.join(format!("{KVER}.conf"))).unwrap();
        put_files_blscfg_skips(&entries);
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        let results = bls_entries(&grub);
        assert!(fails_with(&results, "No boot entries found"), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // --- grubenv, read as GRUB's load_env reads it ---

    /// The boot entries of the root subvolume, from the top level, whose
    /// grubenv is content exactly.
    fn bls_entries_with_grubenv(name: &str, content: &str) -> Vec<CheckResult> {
        let top = scratch(name);
        install_subvol(&top, "root", "", &entry_from_top_level());
        put(&top.join("root/boot/grub2/grubenv"), content);
        let results = bls_entries(&btrfs_context(&top, false, "/root/boot/grub2"));
        fs::remove_dir_all(&top).unwrap();
        results
    }

    // load_env applies each assignment in turn, so the last one holds
    // (grub-core/lib/envblk.c, grub_envblk_iterate).
    #[test]
    fn grubenv_last_assignment_holds() {
        let results = bls_entries_with_grubenv("grubenv-last",
            &grubenv("blsdir=/elsewhere\nblsdir=/root/boot/loader/entries\n"));
        assert!(passes(&results), "{results:?}");
    }

    // A backslash makes the next character part of the value
    // (grub-core/lib/envblk.c, grub_envblk_iterate).
    #[test]
    fn grubenv_value_is_unescaped() {
        let results = bls_entries_with_grubenv("grubenv-escape",
            &grubenv("blsdir=/root/boot/loader/entr\\ies\n"));
        assert!(passes(&results), "{results:?}");
    }

    // load_env refuses a block that does not start with the signature
    // (grub-core/lib/envblk.c, grub_envblk_open), so blsdir stays unset.
    #[test]
    fn grubenv_without_its_signature_sets_nothing() {
        let results = bls_entries_with_grubenv("grubenv-signature",
            &format!("blsdir=/root/boot/loader/entries\n{}", "#".repeat(256)));
        assert!(fails_with(&results, "GRUB finds no boot entry directory"), "{results:?}");
    }

    // --- what grub.cfg sets before blscfg runs ---

    /// The lines of Fedora's generated grub.cfg before blscfg that set
    /// variables: 00_header's load_env of grubenv and of env_block
    /// (util/grub.d/00_header.in:56-70), and 01_users's source of user.cfg
    /// (util/grub.d/01_users.in:3-4).
    const GENERATED_GRUB_CFG: &str = "\
set pager=1

if [ -f ${config_directory}/grubenv ]; then
  load_env -f ${config_directory}/grubenv
elif [ -s $prefix/grubenv ]; then
  load_env
fi

if [ \"${env_block}\" ] ; then
  if [ \"${dev}\" ]; then
    set env_block=\"(${dev})${env_block}\"
  else
    set env_block=\"(${root})${env_block}\"
  fi
  export env_block
  load_env -f \"${env_block}\"
fi

if [ -f ${prefix}/user.cfg ]; then
  source ${prefix}/user.cfg
  if [ -n \"${GRUB2_PASSWORD}\" ]; then
    set superusers=\"root\"
    export superusers
    password_pbkdf2 root ${GRUB2_PASSWORD}
  fi
fi

insmod blscfg
blscfg
";

    const STUB_TOP_LEVEL_PREFIX: &str = "/root/boot/grub2";

    /// The root subvolume laid out under top with Fedora's generated
    /// grub.cfg and the grubenv variables vars, and the context GRUB
    /// builds under Fedora's stub, which leaves btrfs_relative_path unset.
    fn generated_layout(name: &str, vars: &str, entry: &str) -> (PathBuf, Result<GrubContext, GrubContextError>) {
        let top = scratch(name);
        install_subvol(&top, "root", vars, entry);
        put(&top.join("root/boot/grub2/grub.cfg"), GENERATED_GRUB_CFG);
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
        (top, grub)
    }

    fn cannot_verify_naming(grub: Result<GrubContext, GrubContextError>, needle: &str) -> bool {
        matches!(grub, Err(GrubContextError::CannotVerify(reason)) if reason.contains(needle))
    }

    #[test]
    fn the_generated_grub_cfg_builds_a_context() {
        let (top, grub) = generated_layout("phase-generated", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        assert!(passes(&bls_entries(&grub.unwrap())));
        fs::remove_dir_all(&top).unwrap();
    }

    // grub.cfg loads grubenv before blscfg, and GRUB's Btrfs driver reads
    // btrfs_relative_path at each mount (btrfs.c, grub_btrfs_mount and
    // find_path): grub.cfg is looked up from the top level, as the stub
    // leaves it, and the entries and kernels from the default subvolume.
    #[test]
    fn grubenv_btrfs_relative_path_applies_after_grub_cfg_is_read() {
        let (top, grub) = generated_layout("phase-relative", "btrfs_relative_path=1\n", &entry_from_root_subvol());
        let grub = grub.unwrap();

        assert!(passes(&check_grub_cfg(&grub, None)), "{:?}", check_grub_cfg(&grub, None));
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn grubenv_btrfs_subvol_with_btrfs_relative_path_is_refused() {
        let (top, grub) = generated_layout("phase-subvol", "btrfs_relative_path=1\nbtrfs_subvol=root\n",
            &entry_from_root_subvol());
        assert!(matches!(&grub, Err(GrubContextError::Other(msg)) if msg.contains("grubenv sets btrfs_subvol,")), "{:?}", grub.as_ref().err());
        fs::remove_dir_all(&top).unwrap();
    }

    // An empty btrfs_subvol, as grub2-editenv leaves it after unset, names
    // no subvolume (btrfs.c, lookup_root_by_name).
    #[test]
    fn grubenv_empty_btrfs_subvol_with_btrfs_relative_path_is_followed() {
        let (top, grub) = generated_layout("phase-subvol-empty", "btrfs_relative_path=1\nbtrfs_subvol=\n",
            &entry_from_root_subvol());
        assert!(grub.as_ref().is_ok_and(|grub| passes(&bls_entries(grub))), "{:?}", grub.as_ref().err());
        fs::remove_dir_all(&top).unwrap();
    }

    // The stub's variables reach grub.cfg: configfile copies every
    // variable into the context it opens (normal/context.c,
    // grub_env_new_context).
    #[test]
    fn the_stubs_blsdir_reaches_blscfg() {
        let top = scratch("phase-stub-blsdir");
        install_subvol(&top, "root", "", &entry_from_top_level());
        let stub = format!("{BLSDIR_TOP_LEVEL}{}", esp_stub(false, STUB_TOP_LEVEL_PREFIX));
        let grub = context_from_stub(&top, &stub).unwrap();
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    // The header loads env_block from the device the stub found
    // (00_header.in:62-70), with the variables grubenv left.
    #[test]
    fn env_block_is_loaded_from_the_boot_filesystem() {
        let (top, _) = generated_layout("phase-env-block", "env_block=/root/boot/grub2/envblock\n", &entry_from_top_level());
        put(&top.join("root/boot/grub2/envblock"), &grubenv(BLSDIR_TOP_LEVEL));
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    /// An environment block of one 512-byte sector setting vars, padded
    /// with '#' as grub2-editenv pads it.
    fn envblk_sector(vars: &str) -> Vec<u8> {
        let mut block = format!("# GRUB Environment Block\n{vars}").into_bytes();
        block.resize(512, b'#');
        block
    }

    // Fedora's grub2-editenv keeps env_block in sectors a Btrfs filesystem
    // reserves, so grubenv holds env_block=512+1, which the header loads
    // from the device the stub found (00_header.in:62-70): a name that does
    // not start with '/' is a block list (kern/file.c:107-114), here one
    // 512-byte sector at sector 512 (kern/fs.c, grub_fs_blocklist_open).
    // A regular file stands in for the partition.
    #[test]
    fn env_block_as_a_block_list_is_read_from_the_partition() {
        let (top, _) = generated_layout("phase-env-block-sectors", "env_block=512+1\n", &entry_from_top_level());
        let mut partition = vec![0u8; 1024 * 512];
        partition[512 * 512..513 * 512].copy_from_slice(&envblk_sector(BLSDIR_TOP_LEVEL));
        fs::write(top.join("partition"), &partition).unwrap();

        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
        assert!(grub.is_ok(), "{:?}", grub.as_ref().err());
        let results = bls_entries(&grub.unwrap());
        assert!(passes(&results), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // env_block is read from (${dev}); a grubenv that sets dev moves it to
    // a device check does not read.
    #[test]
    fn grubenv_setting_dev_with_env_block_cannot_be_verified() {
        let (top, grub) = generated_layout("phase-env-block-dev", "env_block=/root/boot/grub2/envblock\ndev=hd1,gpt2\n",
            &entry_from_top_level());
        assert!(cannot_verify_naming(grub, "dev"));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn grub_cfg_setting_a_lookup_variable_before_blscfg_cannot_be_verified() {
        for variable in ["btrfs_relative_path", "btrfs_subvol", "btrfs_subvolid", "blsdir"] {
            let top = scratch(&format!("phase-script-{variable}"));
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("set {variable}=x\ninsmod blscfg\nblscfg\n"));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
            assert!(cannot_verify_naming(grub, variable), "{variable}");

            // After blscfg, grub.cfg no longer decides where the entries are.
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("insmod blscfg\nblscfg\nset {variable}=x\n"));
            assert!(context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).is_ok(), "{variable}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // GRUB sets a variable only through a command that assigns it
    // (kern/corecmd.c, set and unset; script/execute.c, NAME=VALUE), so a
    // line that only expands a lookup variable leaves it as it is, and the
    // body of a menu entry runs only when the entry is booted.
    #[test]
    fn grub_cfg_reading_a_lookup_variable_before_blscfg_is_followed() {
        for script in [
            "if [ -z \"${blsdir}\" ]; then echo none; fi",
            "echo $btrfs_relative_path ${btrfs_subvol}",
            "menuentry 'other' {\n  set blsdir=/elsewhere\n}",
        ] {
            let top = scratch("phase-script-read");
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{script}\ninsmod blscfg\nblscfg\n"));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
            assert!(grub.is_ok(), "{script}: {:?}", grub.as_ref().err());
            assert!(passes(&bls_entries(&grub.unwrap())), "{script}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // A command whose variable name, or whose command name, is the value of
    // a variable can set any variable (script/execute.c, grub_script_execute_cmdline).
    #[test]
    fn grub_cfg_assigning_through_an_expansion_before_blscfg_cannot_be_verified() {
        for line in ["set ${x}=/elsewhere", "${x}=/elsewhere", "unset $x", "search --fs-uuid --set=$x 3f2a9c41", "$cmd"] {
            let top = scratch("phase-script-expansion");
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{line}\ninsmod blscfg\nblscfg\n"));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
            assert!(cannot_verify_naming(grub, line), "{line}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // load_env or source other than the generated header's and 01_users's
    // can set any variable.
    #[test]
    fn grub_cfg_loading_other_variables_before_blscfg_cannot_be_verified() {
        for line in ["load_env -f /root/boot/grub2/other", "source /root/boot/grub2/other.cfg"] {
            let top = scratch("phase-script-load");
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{line}\ninsmod blscfg\nblscfg\n"));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
            assert!(cannot_verify_naming(grub, line), "{line}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // 01_users sources user.cfg before blscfg, after the header.
    #[test]
    fn user_cfg_setting_a_lookup_variable_cannot_be_verified() {
        let (top, grub) = generated_layout("phase-user-cfg", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        assert!(grub.is_ok());
        put(&top.join("root/boot/grub2/user.cfg"), "GRUB2_PASSWORD=grub.pbkdf2.sha512.10000.00\n");
        assert!(context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).is_ok());

        put(&top.join("root/boot/grub2/user.cfg"), "blsdir=/elsewhere\n");
        assert!(cannot_verify_naming(context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)), "blsdir"));
        fs::remove_dir_all(&top).unwrap();
    }

    // --- the GRUB_ENV EFI variable ---

    /// GRUB_ENV's data setting vars, laid out as grub2-editenv lays out
    /// grubenv.
    fn grub_env(vars: &str) -> Vec<u8> {
        format!("# GRUB Environment Block\n{vars}").into_bytes()
    }

    // GRUB sets GRUB_ENV's variables when it starts, before it runs the ESP
    // stub (Fedora's grub2 2.12 patches, grub-core/kern/efi/init.c,
    // grub_efi_env_init), so they reach grub.cfg and blscfg as the stub's
    // do. It iterates them without checking the signature, from the byte
    // after it (grub-core/lib/envblk.c, grub_envblk_iterate).
    #[test]
    fn grub_env_variables_reach_blscfg() {
        let top = scratch("grub-env-blsdir");
        install_subvol(&top, "root", "", &entry_from_top_level());
        let stub = esp_stub(false, STUB_TOP_LEVEL_PREFIX);
        let results = bls_entries(&context_from_stub(&top, &stub).unwrap());
        assert!(fails_with(&results, "GRUB finds no boot entry directory"), "{results:?}");

        let grub = context_with_grub_env(&top, &stub, Some(&grub_env(BLSDIR_TOP_LEVEL))).unwrap();
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        let unsigned = format!("{}\n{BLSDIR_TOP_LEVEL}", "x".repeat(24));
        let grub = context_with_grub_env(&top, &stub, Some(unsigned.as_bytes())).unwrap();
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn grub_env_btrfs_relative_path_moves_the_lookup_of_grub_cfg() {
        let top = scratch("grub-env-relative");
        install_subvol(&top, "root", "", &entry_from_root_subvol());
        let grub = context_with_grub_env(&top, &esp_stub(false, "/boot/grub2"),
            Some(&grub_env("btrfs_relative_path=1\n"))).unwrap();
        assert!(passes(&check_grub_cfg(&grub, None)), "{:?}", check_grub_cfg(&grub, None));
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    // The stub's search sets dev and its set prefix= sets prefix, replacing
    // GRUB_ENV's values. The Btrfs driver registers the write hooks of
    // btrfs_subvol and btrfs_subvolid when its module starts, after GRUB has
    // set GRUB_ENV's variables (grub-core/kern/main.c, grub_main: machine
    // init, then the modules), and registering a hook keeps a value without
    // running it (grub-core/kern/env.c, grub_register_variable_hook), so
    // GRUB_ENV's btrfs_subvol points the driver at no subvolume.
    #[test]
    fn grub_env_values_the_stub_or_the_btrfs_driver_replace_are_not_refused() {
        let (top, _) = generated_layout("grub-env-replaced", "env_block=/root/boot/grub2/envblock\n", &entry_from_top_level());
        put(&top.join("root/boot/grub2/envblock"), &grubenv(BLSDIR_TOP_LEVEL));
        let grub = context_with_grub_env(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX),
            Some(&grub_env("dev=hd9,gpt9\nprefix=/elsewhere\n")));
        assert!(grub.as_ref().is_ok_and(|grub| passes(&bls_entries(grub))), "{:?}", grub.as_ref().err());

        let grub = context_with_grub_env(&top, &esp_stub(true, "/boot/grub2"), Some(&grub_env("btrfs_subvol=@\n")));
        assert!(grub.is_ok(), "{:?}", grub.as_ref().err());
        fs::remove_dir_all(&top).unwrap();
    }

    // grub.cfg loads grubenv after the stub, so grubenv replaces GRUB_ENV's
    // value.
    #[test]
    fn grubenv_replaces_a_grub_env_value() {
        let top = scratch("grub-env-grubenv");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = context_with_grub_env(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX),
            Some(&grub_env("blsdir=/elsewhere\n"))).unwrap();
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));
        fs::remove_dir_all(&top).unwrap();
    }

    // --- refusals: each check fails on a seeded defect ---

    // The live root keeps its grub.cfg; the snapshot, whose prefix GRUB
    // reaches through the root subvolume's name after the exchange, does not.
    #[test]
    fn snapshot_check_refuses_a_snapshot_without_grub_cfg() {
        let top = scratch("refuse-snapshot-grub-cfg");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        install_subvol(&top, "snap1", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = snapshot_context(&top, "snap1");
        assert!(passes(&check_grub_cfg(&grub, None)));

        fs::remove_file(top.join("snap1/boot/grub2/grub.cfg")).unwrap();
        let results = check_grub_cfg(&grub, None);
        assert!(fails_with(&results, "file `/root/boot/grub2/grub.cfg' not found"), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn snapshot_check_refuses_a_snapshot_grub_cfg_without_blscfg() {
        let top = scratch("refuse-snapshot-blscfg");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        install_subvol(&top, "snap1", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = snapshot_context(&top, "snap1");

        put(&top.join("snap1/boot/grub2/grub.cfg"), "set timeout=5\n");
        let results = check_grub_cfg(&grub, None);
        assert!(refuses(&results, "does not use Boot Loader Specification entries"), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // grub.cfg lists the boot entries only by running blscfg, or bls_import,
    // which blscfg.c registers as the same command (GRUB_MOD_INIT); loading
    // the module, a comment, or the body of a menu entry does not.
    #[test]
    fn grub_cfg_that_does_not_run_blscfg_is_refused() {
        let top = scratch("refuse-no-blscfg-command");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX);
        let grub_cfg = top.join("root/boot/grub2/grub.cfg");
        for script in ["insmod blscfg\n", "# blscfg\n", "menuentry 'other' {\n  blscfg\n}\n"] {
            put(&grub_cfg, script);
            let results = check_grub_cfg(&grub, None);
            assert!(refuses(&results, "does not use Boot Loader Specification entries"), "{script}: {results:?}");
        }
        put(&grub_cfg, "insmod blscfg\nbls_import\n");
        let results = check_grub_cfg(&grub, None);
        assert!(passes(&results), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // blscfg with an argument lists only some entries, or entries from
    // another directory (blscfg.c, grub_cmd_blscfg).
    #[test]
    fn grub_cfg_running_blscfg_with_an_argument_cannot_be_verified() {
        let top = scratch("blscfg-argument");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put(&top.join("root/boot/grub2/grub.cfg"), "insmod blscfg\nblscfg (hd0,gpt2)/loader/entries\n");
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
        assert!(cannot_verify_naming(grub, "blscfg (hd0,gpt2)/loader/entries"));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn snapshot_check_refuses_a_separate_boot_without_grub_cfg() {
        let boot = scratch("refuse-boot-grub-cfg");
        let grub = separate_boot(&boot);
        assert!(passes(&check_grub_cfg(&grub, None)));

        fs::remove_file(boot.join("grub2/grub.cfg")).unwrap();
        let results = check_grub_cfg(&grub, None);
        assert!(fails_with(&results, "file `/grub2/grub.cfg' not found"), "{results:?}");
        fs::remove_dir_all(&boot).unwrap();
    }

    #[test]
    fn snapshot_check_refuses_a_separate_boot_grub_cfg_without_blscfg() {
        let boot = scratch("refuse-boot-blscfg");
        let grub = separate_boot(&boot);

        put(&boot.join("grub2/grub.cfg"), "set timeout=5\n");
        let results = check_grub_cfg(&grub, None);
        assert!(refuses(&results, "does not use Boot Loader Specification entries"), "{results:?}");
        fs::remove_dir_all(&boot).unwrap();
    }

    #[test]
    fn snapshot_check_refuses_a_kernel_missing_from_a_separate_boot() {
        let boot = scratch("refuse-boot-kernel");
        let grub = separate_boot(&boot);
        assert!(passes(&bls_entries(&grub)));

        fs::remove_file(boot.join(format!("vmlinuz-{KVER}"))).unwrap();
        let results = bls_entries(&grub);
        assert!(fails_with(&results, &format!("file `/vmlinuz-{KVER}' not found")), "{results:?}");
        fs::remove_dir_all(&boot).unwrap();
    }

    #[test]
    fn default_subvol_check_refuses_a_default_other_than_the_root_subvolume() {
        let root = tools::SubvolName::new("root".into());
        assert!(default_subvol_is_root(256, &root, 256).is_ok());

        let err = default_subvol_is_root(5, &root, 256).unwrap_err();
        assert!(err.message().contains("GRUB and Linux see different root filesystems"), "{err}");
        assert!(err.message().contains("set-default 256"), "{err}");
    }

    // --- what Linux will not let check read ---

    // A directory check cannot read is no finding about GRUB: the boot
    // chain may be valid, and check says it cannot verify it.
    #[test]
    fn an_unreadable_boot_entry_directory_cannot_be_verified() {
        use std::os::unix::fs::PermissionsExt;
        let top = scratch("unreadable-entries");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");
        let locked = top.join("root/boot/loader");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::symlink_metadata(locked.join("entries")).is_ok() {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: this process reads directories without permission");
            return;
        }

        let status = evaluate_checks(vec![("Kernel boot entry", bls_entries(&grub))]);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        match status {
            BootStatus::Inaccessible { reason, .. } => {
                assert!(reason.contains("ermission denied") && !reason.contains("not found"), "{reason}");
            }
            BootStatus::Fail(failures) => panic!("reported as a failure: {failures:?}"),
            _ => panic!("reported as verified"),
        }
        fs::remove_dir_all(&top).unwrap();
    }

    // --- what a failure names ---
    //
    // The scratch directory stands in for a temporary mount point, which
    // is gone when the user reads the report: a failure names the GRUB
    // path and where GRUB starts the lookup, never a path below it.

    fn names_grub_path_not_mount(results: &[CheckResult], grub: &GrubContext, top: &Path, grub_path: &str) {
        let top = top.to_str().unwrap();
        let errors: Vec<&str> = results.iter().filter_map(|r| r.as_ref().err()).map(Finding::message).collect();
        assert!(!errors.is_empty());
        assert!(errors.iter().any(|e| e.contains(grub_path)), "{errors:?}");
        assert!(errors.iter().any(|e| e.contains(grub.at_blscfg.describe())), "{errors:?}");
        assert!(errors.iter().all(|e| !e.contains(top)), "{errors:?}");
    }

    #[test]
    fn missing_kernel_is_named_by_its_grub_path() {
        let top = scratch("grub-names-kernel");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_root_subvol());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        names_grub_path_not_mount(&bls_entries(&grub), &grub, &top, &format!("file `/vmlinuz-{KVER}' not found"));
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn missing_grub_cfg_is_named_by_its_grub_path() {
        let top = scratch("grub-names-grub-cfg");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/boot/grub2");

        names_grub_path_not_mount(&check_grub_cfg(&grub, None), &grub, &top, "file `/boot/grub2/grub.cfg' not found");
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn missing_entry_directory_is_named_by_its_grub_paths() {
        let top = scratch("grub-names-blsdir");
        install_subvol(&top, "root", "", &entry_from_top_level());
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        names_grub_path_not_mount(&bls_entries(&grub), &grub, &top, "/boot/loader/entries");
        fs::remove_dir_all(&top).unwrap();
    }

    #[test]
    fn boot_entry_without_linux_is_named_by_its_grub_path() {
        let top = scratch("grub-names-entry");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, "title Fedora Linux\noptions root=UUID=3f2a9c41\n");
        let grub = btrfs_context(&top, false, "/root/boot/grub2");

        let results = bls_entries(&grub);
        let entry = format!("'/root/boot/loader/entries/{KVER}.conf'");
        assert!(fails_with(&results, &entry), "{results:?}");
        assert!(results.iter().all(|r| r.as_ref().err().is_none_or(|e| !e.message().contains(top.to_str().unwrap()))), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // initrd may repeat, a value may list several files, and $variables
    // are GRUB's to expand at boot.
    #[test]
    fn every_initrd_path_must_resolve_and_variables_are_skipped() {
        let top = scratch("grub-initrd");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put(&top.join("root/boot/microcode.img"), "microcode");
        let grub = btrfs_context(&top, false, "/root/boot/grub2");
        let conf = top.join("root/boot/loader/entries/initrd.conf");
        let entry = "/root/boot/loader/entries/initrd.conf";
        let linux = format!("/root/boot/vmlinuz-{KVER}");
        let initramfs = format!("/root/boot/initramfs-{KVER}.img");

        put(&conf, &bls_entry(&linux, &[&format!("{initramfs} $tuned_initrd"), "/root/boot/microcode.img"]));
        assert!(validate(&grub, entry).is_ok());

        put(&conf, &bls_entry(&linux, &[&format!("$tuned_initrd {initramfs} /root/boot/microcode.img")]));
        assert!(validate(&grub, entry).is_ok());

        put(&conf, &bls_entry(&linux, &[&initramfs, "/root/boot/absent.img"]));
        let err = validate(&grub, entry).unwrap_err();
        assert!(err.message().contains("`/root/boot/absent.img'"), "{err}");

        put(&conf, &bls_entry(&linux, &[&format!("{initramfs} /root/boot/absent.img $tuned_initrd")]));
        let err = validate(&grub, entry).unwrap_err();
        assert!(err.message().contains("`/root/boot/absent.img'"), "{err}");

        // The Fedora 44 failure reaches initrd too.
        put(&conf, &bls_entry(&linux, &[&format!("/initramfs-{KVER}.img")]));
        let err = validate(&grub, entry).unwrap_err();
        assert!(err.message().contains(&format!("`/initramfs-{KVER}.img'")), "{err}");

        fs::remove_dir_all(&top).unwrap();
    }
}
