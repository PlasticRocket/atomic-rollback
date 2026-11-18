//! BOOTS predicate: evaluates whether the boot chain is valid by tracing
//! the boot chain from UEFI firmware through GRUB to the root filesystem.
//! Each check corresponds to a link in the chain:
//!   UEFI -> shim -> GRUB -> grub.cfg -> BLS entries -> kernel -> root mount -> fstab

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::grub::{self, BlsDir, Finding, StartingLookupDir, GrubContext, GrubContextError};
use crate::menu;
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

/// What a group of checks found: the results its verdict rests on, what
/// that verdict counted, and warnings, which do not decide it.
#[derive(Default)]
struct Group {
    results: Vec<CheckResult>,
    counted: Vec<String>,
    warnings: Vec<String>,
}

impl From<Vec<CheckResult>> for Group {
    fn from(results: Vec<CheckResult>) -> Self {
        Group { results, ..Group::default() }
    }
}

/// A failure in any group fails the boot chain. Otherwise a group check
/// cannot verify leaves the boot chain unverified, since it may be valid.
/// A warning makes a valid boot chain one with warnings.
fn evaluate_checks(checks: Vec<(&str, Group)>) -> BootStatus {
    let mut all_failures = Vec::new();
    let mut all_unverified = Vec::new();
    let mut warned = false;
    for (name, group) in &checks {
        let failures: Vec<&String> = group.results.iter()
            .filter_map(|r| match r { Err(Finding::Fails(f)) => Some(f), _ => None }).collect();
        let unverified: Vec<&String> = group.results.iter()
            .filter_map(|r| match r { Err(Finding::CannotVerify(f)) => Some(f), _ => None }).collect();
        if !failures.is_empty() {
            println!("  FAIL  {name}");
        } else if !unverified.is_empty() {
            println!("  CANNOT VERIFY  {name}");
        } else if !group.warnings.is_empty() {
            println!("  WARN  {name}");
        } else {
            println!("  PASS  {name}");
        }
        for line in &group.counted {
            println!("        {line}");
        }
        for f in &failures {
            println!("        {f}");
            all_failures.push(format!("{name}: {f}"));
        }
        for f in &unverified {
            println!("        {f}");
            all_unverified.push(format!("{name}: {f}"));
        }
        for warning in &group.warnings {
            println!("        {warning}");
        }
        warned |= !group.warnings.is_empty();
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
        ("EFI boot files", check_esp(root).into()),
        ("GRUB configuration", check_grub_config(root, &grub).into()),
        ("Kernel boot entry", check_bls_entries(&grub, &blsdir)),
        ("Root filesystem", check_root_mountable(root, &grub, &blsdir).into()),
        ("System mounts", check_fstab_mounts(root).into()),
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
        ("GRUB configuration", check_grub_cfg(&grub, None).into()),
        ("Kernel boot entry", check_bls_entries(&grub, &blsdir)),
        ("Root filesystem", check_root_mountable(&snapshot, &grub, &blsdir).into()),
        ("System mounts", check_fstab_mounts(&snapshot).into()),
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

/// A menu entry blscfg adds, and whether GRUB finds its kernel and
/// initramfs.
struct MenuEntry {
    conf: String,
    item: menu::MenuItem,
    verdict: CheckResult,
}

impl MenuEntry {
    /// The entry as check's output names it: its title, its GRUB path and
    /// its place in the menu.
    fn describe(&self, index: usize) -> String {
        format!("'{}' ('{}', entry {} of the menu)", self.item.title, self.conf, index + 1)
    }
}

/// blsdir is the directory blscfg reads boot entries from, as
/// GrubContext::blsdir finds it. The verdict rests on the entry GRUB boots
/// when no key is pressed: the one normal mode picks from default when the
/// menu runs (grub-core/normal/menu.c, run_menu). Another menu entry that
/// does not resolve is a warning.
fn check_bls_entries(grub: &GrubContext, blsdir: &Result<BlsDir, Finding>) -> Group {
    let blsdir = match blsdir {
        Ok(dir) => dir,
        Err(finding) => return vec![Err(finding.clone().map_fails(|e| format!("{e}. GRUB will show an empty menu.")))].into(),
    };

    let entries = match blscfg_entries(grub, blsdir) {
        Ok(entries) => entries,
        Err(finding) => return vec![Err(finding)].into(),
    };

    let mut menu = Vec::new();
    let mut unread: Vec<String> = Vec::new();
    let mut left_out: Vec<String> = Vec::new();
    for entry in &entries {
        let content = match &entry.content {
            Ok(content) => content,
            Err(e) => {
                unread.push(e.clone());
                continue;
            }
        };
        // create_entry leaves an entry without linux out of the menu, and
        // titles one without a title by its linux value (Fedora's grub2
        // 2.12 patches, grub-core/commands/blscfg.c).
        let Some(linux) = parse::bls_field(content, "linux") else {
            left_out.push(format!("'{}', which has no linux line", entry.conf));
            continue;
        };
        let Some(id) = menu::bls_menu_id(&entry.name) else {
            return vec![Err(format!(
                "GRUB never shows its menu: blscfg's create_entry loops forever stripping \".conf\" from \
                 the name of '{}', which without its final \".conf\" still holds \".conf\" before its end. \
                 Rename the entry.", entry.conf).into())].into();
        };
        menu.push(MenuEntry {
            conf: entry.conf.clone(),
            item: menu::MenuItem { id: id.to_string(), title: parse::bls_field(content, "title").unwrap_or(linux).to_string() },
            verdict: validate_bls_entry(grub, &entry.conf, content, linux),
        });
    }

    let not_booted_by_default = |picked: &[usize]| -> Vec<String> {
        menu.iter().enumerate()
            .filter(|(i, _)| !picked.contains(i))
            .filter_map(|(i, entry)| entry.verdict.as_ref().err()
                .map(|finding| format!("{}, which GRUB does not boot by default: {finding}", entry.describe(i))))
            .collect()
    };

    if !unread.is_empty() {
        // An entry check cannot read may stand anywhere in the menu.
        return Group {
            results: unread.into_iter().map(|e| Err(Finding::CannotVerify(e))).collect(),
            warnings: not_booted_by_default(&[]),
            ..Group::default()
        };
    }

    if menu.is_empty() {
        let left_out = if left_out.is_empty() { String::new() } else {
            format!(" blscfg leaves out {}.", left_out.join("; "))
        };
        return vec![Err(format!(
            "No boot entries found in '{}'.{left_out} \
             GRUB will show an empty menu with no kernels to boot. \
             Reinstall the kernel: sudo dnf reinstall kernel-core",
            blsdir.grub_path).into())].into();
    }

    let config = &grub.menu;
    let items: Vec<menu::MenuItem> = menu.iter().map(|entry| entry.item.clone()).collect();
    let (picks, chosen) = match &config.default {
        Ok(default) => (
            menu::default_picks(default.as_ref().map(|d| d.value.as_str()), &items, &config.added),
            match default {
                Some(d) => format!("default is '{}' (from {})", d.value, d.origin),
                None => "default is unset".to_string(),
            },
        ),
        Err(why) => {
            let mut picks: Vec<menu::Pick> = (0..menu.len()).map(menu::Pick::Bls).collect();
            if !config.added.entries.is_empty() {
                picks.push(menu::Pick::Added);
            }
            (picks, format!("check cannot tell default: {why}"))
        }
    };
    let picked: Vec<usize> = picks.iter().filter_map(|pick| match pick {
        menu::Pick::Bls(i) => Some(*i),
        menu::Pick::Added => None,
    }).collect();
    let warnings = not_booted_by_default(&picked);
    let verdict = |results: Vec<CheckResult>, counted: Vec<String>| Group { results, counted, warnings: warnings.clone() };

    if picks.contains(&menu::Pick::Added) {
        return verdict(vec![Err(Finding::CannotVerify(format!(
            "GRUB may boot by default an entry grub.cfg adds after the boot entries, which check does not verify: \
             {chosen}.")))], vec![]);
    }
    let booted = match picked.as_slice() {
        [one] => format!("GRUB boots {} when no key is pressed", menu[*one].describe(*one)),
        several => format!("GRUB boots one of {} when no key is pressed",
            several.iter().map(|&i| menu[i].describe(i)).collect::<Vec<_>>().join(", ")),
    };
    let findings: Vec<&Finding> = picked.iter().filter_map(|&i| menu[i].verdict.as_ref().err()).collect();

    if findings.is_empty() {
        return verdict(vec![Ok(())], vec![format!(
            "{booted}: {chosen}. GRUB finds its kernel and initramfs. \
             check does not count the menu's timeout or a password the entry needs.")]);
    }
    let detail = findings.iter().map(|finding| finding.message()).collect::<Vec<_>>().join(" ");
    if findings.len() == picked.len() && findings.iter().all(|finding| matches!(finding, Finding::Fails(_))) {
        if let Some(fallback) = &config.fallback {
            return verdict(vec![Err(Finding::CannotVerify(format!(
                "{booted}: {chosen}. {detail} GRUB then tries the entries fallback names ({fallback}), \
                 which check does not follow.")))], vec![]);
        }
        return verdict(vec![Err(Finding::Fails(format!(
            "{booted}: {chosen}. {detail}")))], vec![]);
    }
    verdict(vec![Err(Finding::CannotVerify(format!("{booted}: {chosen}. {detail}")))], vec![])
}

/// The files in blsdir whose names blscfg reads as boot entries, each as
/// its name less ".conf" and its GRUB path.
fn bls_entry_files(blsdir: &BlsDir) -> Result<Vec<(String, String)>, Finding> {
    let unverified = |e: std::io::Error| Finding::CannotVerify(format!(
        "cannot verify the boot entries in '{}': {e}", blsdir.grub_path));
    let mut files = Vec::new();
    for entry in fs::read_dir(&blsdir.linux).map_err(unverified)? {
        let name = entry.map_err(unverified)?.file_name();
        if !is_bls_entry_name(name.as_bytes()) {
            continue;
        }
        let name = name.into_string().map_err(|name| Finding::CannotVerify(format!(
            "cannot verify the boot entry {name:?} in '{}': its name is not UTF-8, which check does not look up",
            blsdir.grub_path)))?;
        let conf = blsdir.entry(&name);
        files.push((name[..name.len() - BLS_ENTRY_SUFFIX.len()].to_string(), conf));
    }
    Ok(files)
}

/// A file blscfg reads as a boot entry.
struct BlsEntry {
    /// Its file name less ".conf", by which blscfg orders it and
    /// create_entry names it.
    name: String,
    /// Its GRUB path.
    conf: String,
    /// What GRUB reads in it, or why check cannot read it.
    content: Result<String, String>,
}

/// The files blscfg reads as boot entries from blsdir, in the order it
/// lists them: newest first by bls_cmp, as bls_add_entry inserts them
/// (Fedora's grub2 2.12 patches, grub-core/commands/blscfg.c). blscfg skips
/// a file it cannot open (read_entry). Where the order depends on the
/// order GRUB reads the directory in, check cannot verify the menu.
fn blscfg_entries(grub: &GrubContext, blsdir: &BlsDir) -> Result<Vec<BlsEntry>, Finding> {
    let mut entries = Vec::new();
    for (name, conf) in bls_entry_files(blsdir)? {
        let content = match read_grub_file(&grub.at_blscfg, &conf) {
            Ok(content) => Ok(content),
            Err(Finding::Fails(_)) => continue,
            Err(Finding::CannotVerify(e)) => Err(e),
        };
        entries.push(BlsEntry { name, conf, content });
    }
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    let file = |name: &str| blsdir.entry(&format!("{name}.conf"));
    let order = menu::blscfg_order(&names).map_err(|unknown| Finding::CannotVerify(match unknown {
        menu::UnknownOrder::SameVersion(a, b) => format!(
            "cannot verify the menu: blscfg compares '{}' and '{}' as the same version and keeps the one \
             GRUB reads first, in an order check does not read", file(&a), file(&b)),
        menu::UnknownOrder::Unordered(a, b) => format!(
            "cannot verify the menu: blscfg's comparison does not order '{}' and '{}' as it orders the \
             other entries, so their order depends on the order GRUB reads them in, which check does not read",
            file(&a), file(&b)),
    }))?;
    let mut rank = vec![0; order.len()];
    for (position, &index) in order.iter().enumerate() {
        rank[index] = position;
    }
    let mut ranked: Vec<(usize, BlsEntry)> = rank.into_iter().zip(entries).collect();
    ranked.sort_by_key(|&(position, _)| position);
    Ok(ranked.into_iter().map(|(_, entry)| entry).collect())
}

/// Whether blscfg reads the file of this name in the boot entry directory:
/// it skips a name that starts with '.', has 5 bytes or fewer, or does not
/// end in ".conf" (Fedora's grub2 2.12 patches,
/// grub-core/commands/blscfg.c, read_entry).
fn is_bls_entry_name(name: &[u8]) -> bool {
    name.first() != Some(&b'.') && name.len() > BLS_ENTRY_SUFFIX.len() && name.ends_with(BLS_ENTRY_SUFFIX.as_bytes())
}

/// The suffix of the names blscfg reads as boot entries (read_entry).
const BLS_ENTRY_SUFFIX: &str = ".conf";

// BLS fields may contain GRUB variables after the file path:
//   initrd /initramfs-6.19.9.img $tuned_initrd
// Only the first token is a file path. The rest is GRUB's concern.
// conf is the entry's GRUB path, content what GRUB reads there, and linux
// its linux value.
fn validate_bls_entry(grub: &GrubContext, conf: &str, content: &str, linux: &str) -> CheckResult {
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
    for (_, conf) in bls_entry_files(blsdir)? {
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

    /// The lines of Fedora's generated grub.cfg that load grubenv
    /// (util/grub.d/00_header.in:56-60).
    const LOAD_GRUBENV: &str = "\
if [ -f ${config_directory}/grubenv ]; then
  load_env -f ${config_directory}/grubenv
elif [ -s $prefix/grubenv ]; then
  load_env
fi
";

    /// The line of Fedora's generated grub.cfg that sets root to the boot
    /// filesystem, which the stubs here name by UUID 3f2a9c41
    /// (util/grub-mkconfig_lib.in, prepare_grub_to_access_device).
    const SEARCH_ROOT: &str = "search --no-floppy --fs-uuid --set=root 3f2a9c41\n";

    /// A grub.cfg that loads grubenv, sets root, then lists the boot
    /// entries.
    fn grub_cfg() -> String {
        format!("{LOAD_GRUBENV}{SEARCH_ROOT}insmod blscfg\nblscfg\n")
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
        put(&dir.join("boot/grub2/grub.cfg"), &grub_cfg());
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
        check_bls_entries(grub, &grub.blsdir()).results
    }

    fn validate(grub: &GrubContext, conf: &str) -> CheckResult {
        let content = read_grub_file(&grub.at_blscfg, conf)?;
        validate_bls_entry(grub, conf, &content, parse::bls_field(&content, "linux").unwrap())
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
        put(&boot.join("grub2/grub.cfg"), &grub_cfg());
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
        put(&boot.join("grub2/grub.cfg"), &grub_cfg());
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

    // --- the entries blscfg adds to the menu ---

    // create_entry leaves an entry without a linux line out of the menu
    // (Fedora's grub2 2.12 patches, grub-core/commands/blscfg.c,
    // create_entry): it is no broken menu entry.
    #[test]
    fn an_entry_without_linux_is_left_out_of_the_menu() {
        let top = scratch("menu-no-linux");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put(&top.join("root/boot/loader/entries/notes.conf"), "title Notes\noptions root=UUID=3f2a9c41\n");
        let grub = btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX);
        assert!(passes(&bls_entries(&grub)), "{:?}", bls_entries(&grub));

        fs::remove_file(top.join(format!("root/boot/loader/entries/{KVER}.conf"))).unwrap();
        let results = bls_entries(&grub);
        assert!(fails_with(&results, "'/root/boot/loader/entries/notes.conf', which has no linux line"), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // bls_add_entry drops an entry that compares as the same version as one
    // already listed (blscfg.c, bls_add_entry), keeping whichever GRUB read
    // first, in an order check does not read.
    #[test]
    fn entries_of_the_same_version_cannot_be_verified() {
        let top = scratch("menu-same-version");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put(&top.join("root/boot/loader/entries/6.19.09-200.fc45.x86_64.conf"), &entry_from_top_level());
        let results = bls_entries(&btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX));
        assert!(results.iter().any(|r| matches!(r, Err(Finding::CannotVerify(e))
            if e.contains(KVER) && e.contains("6.19.09-200.fc45.x86_64"))), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
    }

    // create_entry's loop that strips ".conf" never ends for a name, less
    // its final ".conf", whose first ".conf" is not at its end (blscfg.c,
    // create_entry), so GRUB never shows the menu.
    #[test]
    fn an_entry_whose_id_create_entry_cannot_strip_fails() {
        let top = scratch("menu-loop");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        put(&top.join("root/boot/loader/entries/x.confd-1.conf"), &entry_from_top_level());
        let results = bls_entries(&btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX));
        assert!(fails_with(&results, "x.confd-1.conf"), "{results:?}");
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

    // grubenv sets variables only where grub.cfg loads it, which Fedora's
    // generated header does before blscfg (util/grub.d/00_header.in:56-60).
    #[test]
    fn grubenv_applies_only_where_grub_cfg_loads_it() {
        let top = scratch("grubenv-where-loaded");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub_cfg_path = top.join("root/boot/grub2/grub.cfg");
        for script in [format!("{SEARCH_ROOT}insmod blscfg\nblscfg\n"), format!("{SEARCH_ROOT}insmod blscfg\nblscfg\n{LOAD_GRUBENV}")] {
            put(&grub_cfg_path, &script);
            let results = bls_entries(&btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX));
            assert!(fails_with(&results, "GRUB finds no boot entry directory"), "{script}: {results:?}");
        }
        put(&grub_cfg_path, &grub_cfg());
        assert!(passes(&bls_entries(&btrfs_context(&top, false, STUB_TOP_LEVEL_PREFIX))));
        fs::remove_dir_all(&top).unwrap();
    }

    // The header loads env_block where it sets it, after grubenv
    // (00_header.in:62-70).
    #[test]
    fn env_block_applies_only_where_grub_cfg_loads_it() {
        let (top, _) = generated_layout("env-block-where-loaded", "env_block=/root/boot/grub2/envblock\n", &entry_from_top_level());
        put(&top.join("root/boot/grub2/envblock"), &grubenv(BLSDIR_TOP_LEVEL));
        put(&top.join("root/boot/grub2/grub.cfg"), &grub_cfg());
        let results = bls_entries(&context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap());
        assert!(fails_with(&results, "GRUB finds no boot entry directory"), "{results:?}");
        fs::remove_dir_all(&top).unwrap();
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

    /// Fedora's generated grub.cfg, as grub2-mkconfig wrote it on a Fedora 45
    /// test install whose /etc/default/grub sets GRUB_DEFAULT=saved, with
    /// synthetic filesystem UUIDs: 00_header loads grubenv and env_block
    /// (util/grub.d/00_header.in:56-70) and sets default (:92-103), 01_users
    /// sources user.cfg (util/grub.d/01_users.in:3-10), 08_fallback_counting
    /// may set default (08_fallback_counting.in:12-27), 10_linux sets root
    /// and runs blscfg, and after it 10_reset_boot_success, 14_menu_show_once,
    /// 25_bli, 30_uefi-firmware and 41_custom run.
    const GENERATED_GRUB_CFG: &str = r##"#
# DO NOT EDIT THIS FILE
#
# It is automatically generated by grub2-mkconfig using templates
# from /etc/grub.d and settings from /etc/default/grub
#

### BEGIN /etc/grub.d/00_header ###
set pager=1

if [ -f ${config_directory}/grubenv ]; then
  load_env -f ${config_directory}/grubenv
elif [ -s $prefix/grubenv ]; then
  load_env
fi

if [ "${env_block}" ] ; then
  if [ "${dev}" ]; then
    set env_block="(${dev})${env_block}"
  else
    set env_block="(${root})${env_block}"
  fi
  export env_block
  load_env -f "${env_block}"
fi

if [ "${next_entry}" ] ; then
   set default="${next_entry}"
   set next_entry=
   if [ "${env_block}" ] ; then
     save_env -f "${env_block}" next_entry
   else
     save_env next_entry
   fi
   set boot_once=true
else
   set default="${saved_entry}"
fi

if [ x"${feature_menuentry_id}" = xy ]; then
  menuentry_id_option="--id"
else
  menuentry_id_option=""
fi

export menuentry_id_option

if [ "${prev_saved_entry}" ]; then
  set saved_entry="${prev_saved_entry}"
  save_env saved_entry
  set prev_saved_entry=
  save_env prev_saved_entry
  set boot_once=true
fi

function savedefault {
  if [ -z "${boot_once}" ]; then
    saved_entry="${chosen}"
    if [ "${env_block}" ] ; then
      save_env -f "${env_block}" saved_entry
    else
      save_env saved_entry
    fi

  fi
}

function load_video {
  if [ x$feature_all_video_module = xy ]; then
    insmod all_video
  else
    insmod efi_gop
    insmod efi_uga
    insmod ieee1275_fb
    insmod vbe
    insmod vga
    insmod video_bochs
    insmod video_cirrus
  fi
}

serial --speed=115200
terminal_input serial console
terminal_output serial console
if [ x$feature_timeout_style = xy ] ; then
  set timeout_style=menu
  set timeout=5
# Fallback normal timeout code in case the timeout_style feature is
# unavailable.
else
  set timeout=5
fi
### END /etc/grub.d/00_header ###

### BEGIN /etc/grub.d/01_users ###
if [ -f ${prefix}/user.cfg ]; then
  source ${prefix}/user.cfg
  if [ -n "${GRUB2_PASSWORD}" ]; then
    set superusers="root"
    export superusers
    password_pbkdf2 root ${GRUB2_PASSWORD}
  fi
fi
### END /etc/grub.d/01_users ###

### BEGIN /etc/grub.d/08_fallback_counting ###
insmod increment
# Check if boot_counter exists and boot_success=0 to activate this behaviour.
if [ -n "${boot_counter}" -a "${boot_success}" = "0" ]; then
  # if countdown has ended, choose to boot rollback deployment,
  # i.e. default=1 on OSTree-based systems.
  if  [ "${boot_counter}" = "0" -o "${boot_counter}" = "-1" ]; then
    set default=1
    set boot_counter=-1
  # otherwise decrement boot_counter
  else
    decrement boot_counter
  fi
  if [ "${env_block}" ]; then
    save_env -f "${env_block}" boot_counter
  else
    save_env boot_counter
  fi
fi
### END /etc/grub.d/08_fallback_counting ###

### BEGIN /etc/grub.d/10_linux ###
insmod part_gpt
insmod btrfs
search --no-floppy --fs-uuid --set=root 3f2a9c41
insmod part_gpt
insmod fat
search --no-floppy --fs-uuid --set=boot 0A1B-2C3D

# This section was generated by a script. Do not modify the generated file - all changes
# will be lost the next time file is regenerated. Instead edit the BootLoaderSpec files.
#
# The blscfg command parses the BootLoaderSpec files stored in /boot/loader/entries and
# populates the boot menu. Please refer to the Boot Loader Specification documentation
# for the files format: https://systemd.io/BOOT_LOADER_SPECIFICATION/.

# The kernelopts variable should be defined in the grubenv file. But to ensure that menu
# entries populated from BootLoaderSpec files that use this variable work correctly even
# without a grubenv file, define a fallback kernelopts variable if this has not been set.
#
# The kernelopts variable in the grubenv file can be modified using the grubby tool or by
# executing the grub2-mkconfig tool. For the latter, the values of the GRUB_CMDLINE_LINUX
# and GRUB_CMDLINE_LINUX_DEFAULT options from /etc/default/grub file are used to set both
# the kernelopts variable in the grubenv file and the fallback kernelopts variable.
if [ -z "${kernelopts}" ]; then
  set kernelopts="root=UUID=3f2a9c41 ro rootflags=subvol=root "
fi

insmod blscfg
blscfg
### END /etc/grub.d/10_linux ###

### BEGIN /etc/grub.d/10_reset_boot_success ###
# Hiding the menu is ok if last boot was ok or if this is a first boot attempt to boot the entry
if [ "${boot_success}" = "1" -o "${boot_indeterminate}" = "1" ]; then
  set menu_hide_ok=1
else
  set menu_hide_ok=0 
fi
# Reset boot_indeterminate after a successful boot
if [ "${boot_success}" = "1" ] ; then
  set boot_indeterminate=0
# Avoid boot_indeterminate causing the menu to be hidden more than once
elif [ "${boot_indeterminate}" = "1" ]; then
  set boot_indeterminate=2
fi
# Reset boot_success for current boot 
set boot_success=0
if [ "${env_block}" ]; then
  save_env -f "${env_block}" boot_success boot_indeterminate
else
  save_env boot_success boot_indeterminate
fi
### END /etc/grub.d/10_reset_boot_success ###

### BEGIN /etc/grub.d/12_menu_auto_hide ###
### END /etc/grub.d/12_menu_auto_hide ###

### BEGIN /etc/grub.d/14_menu_show_once ###
if [ x$feature_timeout_style = xy ]; then
  if [ "${menu_show_once_timeout}" ]; then
    set timeout_style=menu
    set timeout="${menu_show_once_timeout}"
    unset menu_show_once_timeout
    if [ "${env_block}" ]; then
      save_env -f "${env_block}" menu_show_once_timeout
    else
      save_env menu_show_once_timeout
    fi
  fi
fi
### END /etc/grub.d/14_menu_show_once ###

### BEGIN /etc/grub.d/20_linux_xen ###

### END /etc/grub.d/20_linux_xen ###

### BEGIN /etc/grub.d/20_ppc_terminfo ###
### END /etc/grub.d/20_ppc_terminfo ###

### BEGIN /etc/grub.d/25_bli ###
if [ "$grub_platform" = "efi" ]; then
        if [ ! insmod bli ]; then
                echo "bli module not available"
        fi
fi
### END /etc/grub.d/25_bli ###

### BEGIN /etc/grub.d/30_os-prober ###
### END /etc/grub.d/30_os-prober ###

### BEGIN /etc/grub.d/30_uefi-firmware ###
if [ "$grub_platform" = "efi" ]; then
	if [ fwsetup --is-supported ]; then
		menuentry 'UEFI Firmware Settings' $menuentry_id_option 'uefi-firmware' {
			fwsetup
		}
	fi
fi
### END /etc/grub.d/30_uefi-firmware ###

### BEGIN /etc/grub.d/35_fwupd ###
### END /etc/grub.d/35_fwupd ###

### BEGIN /etc/grub.d/40_custom ###
# This file provides an easy way to add custom menu entries.  Simply type the
# menu entries you want to add after this comment.  Be careful not to change
# the 'exec tail' line above.
### END /etc/grub.d/40_custom ###

### BEGIN /etc/grub.d/41_custom ###
if [ -f  ${config_directory}/custom.cfg ]; then
  source ${config_directory}/custom.cfg
elif [ -z "${config_directory}" -a -f  $prefix/custom.cfg ]; then
  source $prefix/custom.cfg
fi
### END /etc/grub.d/41_custom ###
"##;

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

    // --- the entry GRUB boots without a key press ---

    /// An older kernel than KVER, whose entry blscfg lists second and whose
    /// kernel and initramfs the layouts here do not hold.
    const OLDER: &str = "6.18.1-100.fc45.x86_64";

    fn older_entry() -> String {
        bls_entry(&format!("/root/boot/vmlinuz-{OLDER}"), &[&format!("/root/boot/initramfs-{OLDER}.img")])
            .replace(&format!("({KVER})"), &format!("({OLDER})"))
    }

    /// Fedora's generated grub.cfg with GRUB_DEFAULT written as grub_default
    /// over the root subvolume holding KVER's entry and the broken entry of
    /// OLDER, with the grubenv variables vars.
    fn two_kernels(name: &str, grub_default: &str, vars: &str) -> (PathBuf, GrubContext) {
        let top = scratch(name);
        install_subvol(&top, "root", &format!("{BLSDIR_TOP_LEVEL}{vars}"), &entry_from_top_level());
        put(&top.join(format!("root/boot/loader/entries/{OLDER}.conf")), &older_entry());
        put(&top.join("root/boot/grub2/grub.cfg"),
            &GENERATED_GRUB_CFG.replace("set default=\"${saved_entry}\"", &format!("set default=\"{grub_default}\"")));
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        (top, grub)
    }

    fn kernel_entry_status(grub: &GrubContext) -> BootStatus {
        evaluate_checks(vec![("Kernel boot entry", check_bls_entries(grub, &grub.blsdir()))])
    }

    fn fails_naming(status: BootStatus, needle: &str) -> bool {
        matches!(status, BootStatus::Fail(failures) if failures.iter().any(|f| f.contains(needle)))
    }

    fn cannot_verify(status: BootStatus, needle: &str) -> bool {
        matches!(status, BootStatus::Inaccessible { reason, .. } if reason.contains(needle))
    }

    // run_menu boots entry get_entry_number(default), the first when that
    // is no entry (grub-core/normal/menu.c), and 00_header sets default to
    // saved_entry (util/grub.d/00_header.in:92-103): a broken default entry
    // beside a working one leaves the machine unable to boot unattended.
    #[test]
    fn a_broken_default_entry_fails_beside_a_working_one() {
        let (top, grub) = two_kernels("default-broken", "${saved_entry}", &format!("saved_entry={OLDER}\n"));
        assert!(fails_naming(kernel_entry_status(&grub), &format!("`/root/boot/vmlinuz-{OLDER}'")));
        fs::remove_dir_all(&top).unwrap();
    }

    // blscfg lists KVER first, so a default that names no entry, or is
    // unset, boots it.
    #[test]
    fn a_working_default_entry_passes_with_a_warning_for_a_broken_one() {
        for vars in [format!("saved_entry={KVER}\n"), String::new(), "saved_entry=gone-6.1.0\n".to_string()] {
            let (top, grub) = two_kernels("default-works", "${saved_entry}", &vars);
            assert!(matches!(kernel_entry_status(&grub), BootStatus::Warn), "{vars}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // GRUB_DEFAULT=1 names the second entry by its place in the menu.
    #[test]
    fn a_default_by_number_fails_on_the_broken_entry_it_names() {
        let (top, grub) = two_kernels("default-number", "1", "");
        assert!(fails_naming(kernel_entry_status(&grub), OLDER));
        fs::remove_dir_all(&top).unwrap();
    }

    // next_entry, set by grub2-reboot, wins over saved_entry for one boot
    // (00_header.in:92-93).
    #[test]
    fn next_entry_decides_the_default_entry() {
        let (top, grub) = two_kernels("default-next", "${saved_entry}", &format!("saved_entry={KVER}\nnext_entry={OLDER}\n"));
        assert!(fails_naming(kernel_entry_status(&grub), OLDER));
        fs::remove_dir_all(&top).unwrap();
    }

    // 08_fallback_counting sets default to 1 when boot_counter has run out
    // and the last boot did not succeed (08_fallback_counting.in:12-16).
    #[test]
    fn the_boot_counter_decides_the_default_entry_when_it_runs_out() {
        let (top, grub) = two_kernels("default-counter", "${saved_entry}",
            &format!("saved_entry={KVER}\nboot_counter=0\nboot_success=0\n"));
        assert!(fails_naming(kernel_entry_status(&grub), OLDER));
        fs::remove_dir_all(&top).unwrap();

        let (top, grub) = two_kernels("default-counter-success", "${saved_entry}",
            &format!("saved_entry={KVER}\nboot_counter=0\nboot_success=1\n"));
        assert!(matches!(kernel_entry_status(&grub), BootStatus::Warn));
        fs::remove_dir_all(&top).unwrap();
    }

    // When the default entry fails, GRUB tries the entries fallback names
    // (grub-core/normal/menu.c, grub_menu_execute_with_fallback), which
    // check does not follow.
    #[test]
    fn a_broken_default_entry_with_fallback_set_cannot_be_verified() {
        let (top, grub) = two_kernels("default-fallback", "${saved_entry}", &format!("saved_entry={OLDER}\nfallback=0\n"));
        assert!(cannot_verify(kernel_entry_status(&grub), "fallback"));
        fs::remove_dir_all(&top).unwrap();
    }

    // 30_uefi-firmware adds its entry only where fwsetup is supported
    // (util/grub.d/30_uefi-firmware.in:34-40), so a default naming it boots
    // that entry or, without it, the first.
    #[test]
    fn a_default_naming_an_entry_grub_cfg_adds_cannot_be_verified() {
        let (top, grub) = two_kernels("default-firmware", "uefi-firmware", "");
        assert!(cannot_verify(kernel_entry_status(&grub), "uefi-firmware"));
        fs::remove_dir_all(&top).unwrap();
    }

    // The verdict says which entry it counted, why GRUB boots it, and what
    // it does not count.
    #[test]
    fn the_verdict_states_the_entry_it_counted() {
        let (top, grub) = two_kernels("default-counted", "${saved_entry}", &format!("saved_entry={KVER}\n"));
        let group = check_bls_entries(&grub, &grub.blsdir());
        let counted = group.counted.join(" ");
        assert!(counted.contains(&format!("GRUB boots 'Fedora Linux ({KVER})'")), "{counted}");
        assert!(counted.contains("when no key is pressed"), "{counted}");
        assert!(counted.contains(&format!("default is '{KVER}' (from saved_entry in grubenv)")), "{counted}");
        assert!(counted.contains("does not count the menu's timeout"), "{counted}");
        assert!(group.warnings.iter().any(|w| w.contains(OLDER) && w.contains("does not boot by default")), "{:?}", group.warnings);
        fs::remove_dir_all(&top).unwrap();
    }

    // grub_normal_add_menu_entry adds each entry at the end of the menu
    // (grub-core/commands/menuentry.c), so an entry grub.cfg defines before
    // blscfg stands ahead of the boot entries.
    #[test]
    fn a_menu_entry_before_blscfg_cannot_be_verified() {
        let (top, grub) = two_kernels("default-entry-before", "${saved_entry}", &format!("saved_entry={KVER}\n"));
        assert!(matches!(kernel_entry_status(&grub), BootStatus::Warn));
        put(&top.join("root/boot/grub2/grub.cfg"), &GENERATED_GRUB_CFG.replace("insmod blscfg\nblscfg\n",
            "menuentry 'Other' {\n  chainloader /EFI/other.efi\n}\ninsmod blscfg\nblscfg\n"));
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        assert!(cannot_verify(kernel_entry_status(&grub), "grub.cfg adds a menu entry before blscfg"));
        fs::remove_dir_all(&top).unwrap();
    }

    /// The entry os-prober writes for Windows after the boot entries
    /// (util/grub.d/30_os-prober.in), with a synthetic id.
    const OS_PROBER_ENTRY: &str = "\
menuentry 'Windows Boot Manager (on /dev/nvme0n1p1)' --class windows --class os $menuentry_id_option 'osprober-efi-0A1B-2C3D' {
\tinsmod part_gpt
\tchainloader /EFI/Microsoft/Boot/bootmgfw.efi
}
";

    // An entry grub.cfg adds after blscfg on every run is in the menu, with
    // the id after --id (00_header.in:108-112 sets menuentry_id_option).
    #[test]
    fn a_default_naming_an_entry_grub_cfg_always_adds_cannot_be_verified() {
        for (grub_default, by_default) in [("osprober-efi-0A1B-2C3D", false), ("Windows Boot Manager (on /dev/nvme0n1p1)", false), ("2", false), ("0", true)] {
            let top = scratch("default-os-prober");
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join(format!("root/boot/loader/entries/{OLDER}.conf")), &older_entry());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{}{OS_PROBER_ENTRY}",
                GENERATED_GRUB_CFG.replace("set default=\"${saved_entry}\"", &format!("set default=\"{grub_default}\""))));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
            let status = kernel_entry_status(&grub);
            if by_default {
                assert!(matches!(status, BootStatus::Warn), "{grub_default}");
            } else {
                assert!(cannot_verify(status, "an entry grub.cfg adds"), "{grub_default}");
            }
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // user.cfg runs after 00_header sets default (01_users.in:3-4), so it
    // can set default to anything: GRUB boots any entry of the menu, which
    // in Fedora's grub.cfg may hold the UEFI firmware entry.
    #[test]
    fn user_cfg_setting_default_leaves_any_menu_entry_the_default() {
        let (top, grub) = two_kernels("default-user-cfg", "${saved_entry}", &format!("saved_entry={KVER}\n"));
        assert!(matches!(kernel_entry_status(&grub), BootStatus::Warn));
        put(&top.join("root/boot/grub2/user.cfg"), "set default=1\n");
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        assert!(cannot_verify(kernel_entry_status(&grub), "user.cfg sets default"));

        // A menu of boot entries that all resolve boots one that resolves.
        fs::remove_file(top.join(format!("root/boot/loader/entries/{OLDER}.conf"))).unwrap();
        put(&top.join("root/boot/grub2/grub.cfg"),
            &format!("{LOAD_GRUBENV}source ${{prefix}}/user.cfg\n{SEARCH_ROOT}insmod blscfg\nblscfg\n"));
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        assert!(matches!(kernel_entry_status(&grub), BootStatus::Pass));
        fs::remove_dir_all(&top).unwrap();
    }

    // A group with nothing to check passes; it is no warning.
    #[test]
    fn a_group_with_no_results_passes() {
        assert!(matches!(evaluate_checks(vec![("System mounts", Vec::new().into())]), BootStatus::Pass));
    }

    // When check cannot verify the default entry, a broken entry beside it
    // is reported as broken, not as one check cannot verify.
    #[test]
    fn a_broken_entry_beside_a_default_check_cannot_verify_is_not_reported_as_unverified() {
        let (top, _) = generated_layout("default-unverified", &format!("{BLSDIR_TOP_LEVEL}saved_entry={KVER}\n"),
            &bls_entry(&format!("/root/locked/vmlinuz-{KVER}"), &[&format!("/root/boot/initramfs-{KVER}.img")]));
        put(&top.join(format!("root/boot/loader/entries/{OLDER}.conf")), &older_entry());
        put(&top.join(format!("root/locked/vmlinuz-{KVER}")), "kernel");
        let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let locked = top.join("root/locked");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::symlink_metadata(locked.join(format!("vmlinuz-{KVER}"))).is_ok() {
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("skipped: this process reads directories without permission");
            return;
        }
        let status = kernel_entry_status(&grub);
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
        match status {
            BootStatus::Inaccessible { reason, .. } => {
                assert!(reason.contains("ermission denied") && !reason.contains(OLDER), "{reason}");
            }
            _ => panic!("not reported as unverified"),
        }
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

            // After blscfg, blsdir no longer decides where the entries are.
            if variable == "blsdir" {
                put(&top.join("root/boot/grub2/grub.cfg"), &format!("{}set {variable}=x\n", grub_cfg()));
                assert!(context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX)).is_ok(), "{variable}");
            }
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // blscfg reads the boot entries from the device in root (Fedora's grub2
    // 2.12 patches, grub-core/commands/blscfg.c, bls_load_entries), which
    // 10_linux's search sets to the boot filesystem by its UUID
    // (util/grub-mkconfig_lib.in, prepare_grub_to_access_device). Before
    // that, root is the device GRUB started from, the EFI system partition
    // (grub-core/kern/main.c, grub_set_prefix_and_root).
    #[test]
    fn blscfg_reads_the_entries_from_the_device_in_root() {
        let top = scratch("root-device");
        install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        let grub_cfg_path = top.join("root/boot/grub2/grub.cfg");
        let stub = esp_stub(false, STUB_TOP_LEVEL_PREFIX);
        for (script, needle) in [
            (format!("{LOAD_GRUBENV}insmod blscfg\nblscfg\n"), "EFI system partition"),
            (format!("{LOAD_GRUBENV}search --no-floppy --fs-uuid --set=root 0badc0de\nblscfg\n"), "UUID=0badc0de"),
            (format!("{LOAD_GRUBENV}{SEARCH_ROOT}set root=hd1,gpt2\nblscfg\n"), "set root=hd1,gpt2"),
            (format!("{LOAD_GRUBENV}{SEARCH_ROOT}search --set 0badc0de\nblscfg\n"), "search --set 0badc0de"),
        ] {
            put(&grub_cfg_path, &script);
            assert!(cannot_verify_naming(context_from_stub(&top, &stub), needle), "{script}");
        }

        // grubenv sets root where grub.cfg loads it: before the search, the
        // search replaces it; after, it holds.
        put(&top.join("root/boot/grub2/grubenv"), &grubenv(&format!("{BLSDIR_TOP_LEVEL}root=hd1,gpt2\n")));
        put(&grub_cfg_path, &format!("{SEARCH_ROOT}{LOAD_GRUBENV}blscfg\n"));
        assert!(cannot_verify_naming(context_from_stub(&top, &stub), "grubenv sets root"));
        put(&grub_cfg_path, &grub_cfg());
        assert!(context_from_stub(&top, &stub).is_ok());
        put(&top.join("root/boot/grub2/grubenv"), &grubenv(BLSDIR_TOP_LEVEL));

        // The compatibility line before the search, hints, and the case of
        // the UUID, which search compares without it (commands/search.c).
        put(&grub_cfg_path, &format!("{LOAD_GRUBENV}set root='hd0,gpt2'\n\
            if [ x$feature_platform_search_hint = xy ]; then\n\
              search --no-floppy --fs-uuid --set=root --hint-efi=hd0,gpt2 3F2A9C41\n\
            else\n  search --no-floppy --fs-uuid --set=root 3f2a9c41\nfi\nblscfg\n"));
        let grub = context_from_stub(&top, &stub);
        assert!(grub.as_ref().is_ok_and(|grub| passes(&bls_entries(grub))), "{:?}", grub.as_ref().err());
        fs::remove_dir_all(&top).unwrap();
    }

    // A menu entry blscfg adds looks its kernel up when it is booted,
    // with the variables grub.cfg leaves: its linux and initrd lines name
    // ($root) (blscfg.c, create_entry), and GRUB's Btrfs driver reads
    // btrfs_relative_path, btrfs_subvol and btrfs_subvolid at each mount
    // (btrfs.c, grub_btrfs_mount). So after blscfg, grub.cfg and the
    // custom.cfg 41_custom sources (util/grub.d/41_custom.in:3-7) must not
    // set those or root, and a second blscfg adds entries read with other
    // values.
    #[test]
    fn grub_cfg_moving_the_kernel_lookup_after_blscfg_cannot_be_verified() {
        let (top, grub) = generated_layout("after-blscfg", BLSDIR_TOP_LEVEL, &entry_from_top_level());
        assert!(grub.is_ok(), "{:?}", grub.as_ref().err());
        let stub = esp_stub(false, STUB_TOP_LEVEL_PREFIX);
        for (line, needle) in [
            ("set btrfs_relative_path=1", "btrfs_relative_path"),
            ("set btrfs_subvol=@", "btrfs_subvol"),
            ("btrfs_subvolid=256", "btrfs_subvolid"),
            ("set root=hd1,gpt2", "root"),
            (SEARCH_ROOT.trim(), "root"),
            ("source /root/boot/grub2/other.cfg", "other.cfg"),
            ("blscfg", "blscfg"),
            ("set config_directory=/elsewhere", "config_directory"),
        ] {
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{GENERATED_GRUB_CFG}{line}\n"));
            assert!(cannot_verify_naming(context_from_stub(&top, &stub), needle), "grub.cfg: {line}");
            put(&top.join("root/boot/grub2/grub.cfg"), GENERATED_GRUB_CFG);
            put(&top.join("root/boot/grub2/custom.cfg"), &format!("{line}\n"));
            assert!(cannot_verify_naming(context_from_stub(&top, &stub), "custom.cfg"), "custom.cfg: {line}");
            fs::remove_file(top.join("root/boot/grub2/custom.cfg")).unwrap();
        }

        // blsdir and the variables 10_reset_boot_success sets are not read
        // once blscfg has listed the entries.
        put(&top.join("root/boot/grub2/custom.cfg"), "set blsdir=/elsewhere\nset boot_success=0\n");
        assert!(context_from_stub(&top, &stub).is_ok());
        fs::remove_dir_all(&top).unwrap();
    }

    // env_block and dev name where the header loads env_block, prefix where
    // 01_users reads user.cfg, and config_directory where the header reads
    // grubenv (00_header.in:56-70, 01_users.in:3-4), so grub.cfg setting one
    // before blscfg moves a load check follows.
    #[test]
    fn grub_cfg_setting_where_variables_load_from_before_blscfg_cannot_be_verified() {
        for variable in ["env_block", "dev", "prefix", "config_directory"] {
            let top = scratch(&format!("phase-script-{variable}"));
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("set {variable}=x\n{}", grub_cfg()));
            let grub = context_from_stub(&top, &esp_stub(false, STUB_TOP_LEVEL_PREFIX));
            assert!(cannot_verify_naming(grub, variable), "{variable}");
            fs::remove_dir_all(&top).unwrap();
        }
    }

    // GRUB sets a variable only through a command that assigns it
    // (kern/corecmd.c, set and unset; script/execute.c, NAME=VALUE), so a
    // line that only expands a lookup variable leaves it as it is, and the
    // body of a function runs only when it is called.
    #[test]
    fn grub_cfg_reading_a_lookup_variable_before_blscfg_is_followed() {
        for script in [
            "if [ -z \"${blsdir}\" ]; then echo none; fi",
            "echo $btrfs_relative_path ${btrfs_subvol}",
            "function elsewhere {\n  set blsdir=/elsewhere\n}",
        ] {
            let top = scratch("phase-script-read");
            install_subvol(&top, "root", BLSDIR_TOP_LEVEL, &entry_from_top_level());
            put(&top.join("root/boot/grub2/grub.cfg"), &format!("{LOAD_GRUBENV}{script}\n{SEARCH_ROOT}insmod blscfg\nblscfg\n"));
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

        let status = evaluate_checks(vec![("Kernel boot entry", check_bls_entries(&grub, &grub.blsdir()))]);
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
