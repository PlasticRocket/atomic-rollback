//! Rollback: verify boot chain for snapshot, exchange root subvolume
//! names via RENAME_EXCHANGE, update default subvolume. Undoes the
//! exchange if set-default fails.

use std::path::Path;

use crate::consts::{BTRFS_TOPLEVEL_SUBVOLID, TOPLEVEL_MOUNT};
use crate::swap::RenameExchange;
use crate::{check, swap, tools};

/// Cannot use with_toplevel because the undo path needs to exchange back
/// if set-default fails, which requires the mount to stay alive.
pub fn rollback(snapshot_name: &str) -> Result<(), String> {
    let toplevel = TOPLEVEL_MOUNT;
    let (device, fstab) = tools::root_device()?;
    let exchange = RenameExchange {
        root: tools::root_subvol_name(&fstab)?,
        snapshot: tools::SubvolName::new(snapshot_name.to_string()),
    };

    std::fs::create_dir_all(toplevel)
        .map_err(|e| format!("mkdir {toplevel}: {e}"))?;
    tools::mount_subvolid(&device, toplevel, BTRFS_TOPLEVEL_SUBVOLID)?;

    // Verify snapshot exists
    let snapshot_path = format!("{toplevel}/{snapshot_name}");
    if !Path::new(&snapshot_path).exists() {
        tools::umount(toplevel)?;
        return Err(format!("snapshot '{snapshot_name}' not found at top-level"));
    }

    println!("\n  Verifying boot chain for snapshot '{snapshot_name}'...");
    match check::verify_snapshot_bootable(Path::new(toplevel), &exchange) {
        check::BootStatus::Pass | check::BootStatus::Warn => {
            println!("  Snapshot verified.\n");
        }
        check::BootStatus::Fail(failures) => {
            println!("\n  Snapshot verification FAILED:");
            for f in &failures {
                eprintln!("    {f}");
            }
            tools::umount(toplevel)?;
            let _ = std::fs::remove_dir(toplevel);
            return Err("rollback aborted: boot chain invalid for snapshot".into());
        }
        check::BootStatus::Inaccessible { reason, hint } => {
            // Cannot verify snapshot bootability; fail safe rather than
            // proceed with an unchecked RENAME_EXCHANGE.
            println!("\n  Snapshot verification FAILED:");
            eprintln!("    cannot verify boot chain: {reason}");
            eprintln!("    {hint}");
            tools::umount(toplevel)?;
            let _ = std::fs::remove_dir(toplevel);
            return Err("rollback aborted: boot chain could not be verified for snapshot".into());
        }
    }

    check::print_rollback_scope(&fstab);

    println!("  RENAME_EXCHANGE: {} <-> {}", exchange.root, exchange.snapshot);
    swap::rename_exchange(Path::new(toplevel), exchange.root.as_str(), exchange.snapshot.as_str())?;

    // Update default subvolume to match the new root.
    // If this fails, UNDO the exchange so the system is unchanged.
    // The model treats rollback as atomic: both happen or neither.
    let new_root_id = match tools::btrfs_subvol_id_by_name(toplevel, &exchange.root) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("  set-default failed; undoing the exchange to restore original state");
            if let Err(undo_err) = swap::rename_exchange(Path::new(toplevel), exchange.root.as_str(), exchange.snapshot.as_str()) {
                eprintln!("  CRITICAL: undoing the exchange also failed: {undo_err}");
                eprintln!("  System is in an inconsistent state. Manual recovery required.");
            }
            tools::umount(toplevel)?;
            let _ = std::fs::remove_dir(toplevel);
            return Err(format!("rollback aborted: cannot determine new root ID: {e}"));
        }
    };
    println!("  set-default: ID {new_root_id}");
    if let Err(e) = tools::btrfs_subvol_set_default(new_root_id, toplevel) {
        eprintln!("  set-default failed; undoing the exchange to restore original state");
        if let Err(undo_err) = swap::rename_exchange(Path::new(toplevel), exchange.root.as_str(), exchange.snapshot.as_str()) {
            eprintln!("  CRITICAL: undoing the exchange also failed: {undo_err}");
            eprintln!("  System is in an inconsistent state. Manual recovery required.");
        }
        tools::umount(toplevel)?;
        let _ = std::fs::remove_dir(toplevel);
        return Err(format!("rollback aborted: set-default failed: {e}"));
    }

    // The exchange and set-default are in the btrfs in-memory journal only.
    tools::sync_filesystem(toplevel)?;

    // Rollback succeeded. Cleanup is best-effort; a stale mount
    // doesn't affect the boot chain or the rollback.
    let _ = tools::umount(toplevel);
    let _ = std::fs::remove_dir(toplevel);

    Ok(())
}
