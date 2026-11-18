# Changelog

All notable changes to atomic-rollback are documented here.

## [Unreleased]

### Changed

- `check` fails when `btrfs_subvol` or `btrfs_subvolid` names a subvolume while `btrfs_relative_path` is set, on a Btrfs boot filesystem, by the ESP `grub.cfg` or by the `grubenv` that `grub.cfg` loads, naming the variable and where it is set. An empty `btrfs_subvol` or a `btrfs_subvolid` of 0 names none, as GRUB reads them. GRUB reads them only when `btrfs_relative_path` is set, neither Fedora nor atomic-rollback writes them, and `check` does not model which subvolume GRUB then resolves paths from.
- Snapshot retention removes the automatic snapshots created first, by Btrfs creation generation, instead of those with the lowest subvolume IDs, an order Btrfs does not promise. It never removes the default subvolume or the subvolume the running system is mounted from (between a `rollback` and the reboot, that is the old root under the snapshot's automatic name); such a snapshot still counts toward `MAX_SNAPSHOTS`, as snapper counts its default and active snapshots.

### Fixed

- `check` now distinguishes "cannot verify" from "boot chain has problems." Running as non-root on Fedora (where the ESP grub.cfg is root-readable only) previously reported a boot-chain failure with exit 1, misleading users about the actual system state. The tool now reports "cannot verify boot chain" with a prompt to run as root, and exits with code 3 to let scripts distinguish the case. It reports "cannot verify" too when Linux refuses to read a file or directory GRUB reads, with the Linux error, instead of reporting the file missing. Closes #14.
- The boot chain check run by `check`, `rollback`, each step of `setup` and `migrate`, and the kernel hook looks up the files GRUB reads (the ESP stub's prefix, `grub.cfg`, the BLS directory named in `grubenv`, and each boot entry's kernel and initramfs) as GRUB does: on Btrfs from the top-level subvolume, or from the default subvolume when `btrfs_relative_path` is set, which the ESP stub decides for `grub.cfg` and `grubenv` and the variables `grub.cfg` then loads from `grubenv` decide for the boot entries; following symbolic links as GRUB follows them; and counting as boot entries only the files `blscfg` reads. It names each missing file by its GRUB path, and reports that it cannot verify the boot chain when `grub.cfg` sets those variables before `blscfg` other than as its generated header does. It previously looked them up inside the subvolume mounted at `/`, so on a migrated system whose ESP stub Fedora 44 or later had replaced, it reported a valid boot chain while every menu entry failed with `` file `/vmlinuz-...' not found ``; on such a system `check` now reports those entries and `rollback` refuses.
- In 0.4.0, `rollback` refused every rollback on a system set up without `migrate`, whose `/boot` is a separate partition, with `rollback aborted: boot chain invalid for snapshot`: its boot chain check looked for `grub.cfg` and the boot entries inside the snapshot, whose `/boot` is empty. The check now reads `grub.cfg`, the boot entries, and their kernels and initramfs on the live `/boot` partition, which rollback leaves unchanged, and still examines the snapshot for the root filesystem.
- An RPM transaction whose files do not fit beside the snapshot taken before it is refused before anything is written, with the amount it needs, the amount free, and how to free space. The snapshot keeps the old copy of every file the transaction replaces, which rpm's own disk space check counts as freed, and rpm counts each Btrfs subvolume apart, so such a transaction passed rpm's check and failed part way with `No space left on device`, leaving some packages upgraded and others not. The RPM plugin now adds up every file of every package the transaction installs that lands on the Btrfs filesystem holding `/`, in any of its subvolumes, rounded to whole blocks and with rpm's 5% margin as rpm counts, and credits nothing for replaced or removed files. Snapshots are never deleted to make room.
- The boot chain check reads `grub.cfg`, and the `user.cfg` and `custom.cfg` it sources, to its end by what each command assigns, as GRUB runs them: a line that only reads a variable no longer leaves the boot chain unverified, while a command whose variable name is the value of a variable, such as `set ${x}=...`, does; `grubenv`, `env_block` and `user.cfg` apply only where `grub.cfg` loads them; `grub.cfg` must run the `blscfg` command, not only mention it; and a command after `blscfg` that sets `root` or a Btrfs subvolume variable, which move where GRUB finds a booted entry's kernel, leaves the boot chain unverified.
- The boot chain check reads the `GRUB_ENV` EFI variable, whose variables Fedora's GRUB sets when it starts, before the ESP `grub.cfg` runs, so a `blsdir`, `btrfs_relative_path` or `saved_entry` there is followed. It reports that it cannot verify the boot chain when it cannot read efivarfs.
- The boot chain check reads the boot entries from the filesystem that the `search --set=root` line `grub2-mkconfig` writes into `grub.cfg` names, where `blscfg` reads them, instead of assuming the filesystem the ESP `grub.cfg` names. It reports that it cannot verify the boot chain when `grub.cfg` sets `root` another way or to another filesystem.
- `check` counts as boot entries only the entries `blscfg` adds to GRUB's menu: a file without a `linux` line, which `blscfg` leaves out, is no longer reported as a broken entry; two files `blscfg` compares as the same version, of which GRUB keeps the one it reads first, leave the boot chain unverified; and a file whose name, without its final `.conf`, still holds `.conf` before its end, on which `blscfg` loops forever, fails the boot chain.
- `check` judges the boot entries by the entry GRUB boots when no key is pressed, which it finds as Fedora's GRUB does from `next_entry`, `saved_entry` and the boot counter in `grubenv`, the `GRUB_DEFAULT` that `grub2-mkconfig` writes into `grub.cfg`, and the order of the menu, and it fails when GRUB cannot find that entry's kernel or initramfs; other entries that do not resolve are warnings. It previously reported the boot chain valid, with warnings, when any entry resolved, so a broken default entry beside a working one read as valid while the system could not boot unattended. The verdict names the entry it counted. `check` reports that it cannot verify the boot chain where that entry depends on what it does not read, such as a `default` set in `user.cfg`, an entry `grub.cfg` adds only where the firmware supports it, or the `fallback` entries GRUB tries after a broken default, and it does not count the menu timeout or entry passwords.

### Security

- The boot chain check run by `check`, `rollback`, `setup`, `migrate` and the kernel hook makes its temporary read-only mounts in a new directory created by `mkdtemp` under `/run`, which only root can write to. It previously mounted at a predictable path under `/tmp`, which any local user could create beforehand, for example as a symlink, to choose where root mounted and later unmounted a filesystem.

## [0.4.0] - 2026-04-14

### Added

- Automatic snapshots use rolling timestamp names in `%Y-%m-%d_%H-%M-%S` format instead of a fixed `root.pre-update`. Every RPM transaction creates a new snapshot; the history is no longer overwritten on each upgrade. Closes #9.
- Snapshot retention: the tool keeps the most recent `MAX_SNAPSHOTS` automatic snapshots (default 50, configurable in `/etc/atomic-rollback.conf`) and evicts older ones. User-named snapshots are never counted against the limit and are never evicted; unbounded accumulation of user-named snapshots remains the expected behavior.
- `snapshot list` shows a three-column table: btrfs subvolume ID, name, and creation time. Sorted by ID (chronological).
- `rollback [id|name]` and `snapshot delete <id|name>` accept btrfs subvolume IDs (integers) in addition to names. `rollback` with no arguments defaults to the most recent snapshot (highest ID). The IDs are btrfs filesystem primitives, monotonic and never reused, surfaced as the user-facing handle without any atomic-rollback state.
- `snapshot create` output includes the btrfs subvolume ID (e.g. `Snapshot 'foo' with ID 123 created.`) so the new snapshot can be referenced numerically in subsequent commands without running `list` first.
- `check` and `rollback` show rollback scope: directories protected by separate btrfs subvolumes are listed as SAFE (unaffected by rollback), directories inside the root subvolume are listed as RISK (will revert on rollback). Derived from fstab `subvol=` entries and mountpoint checks on top-level directories.
- `--version` and `-V` print the installed version. Output format: `atomic-rollback v<version>`, one line to stdout, matching the `btrfs-progs v6.17` convention.

### Changed

- `check` output and user-facing documentation use "boot chain" terminology instead of "system bootable." The tool verifies boot chain structural validity (the formal model's scope), not system bootability in the broader sense. Kernel bugs, runtime failures, and other post-boot problems are outside what the tool can prove, and the language now matches.
- The kernel-install hook is owned by `migrate` as a migration artifact instead of being installed by the RPM. The hook now persists across atomic-rollback uninstall, so removing the tool on a migrated system does not leave future kernel installs with unbootable BLS entries. Closes #17.

### Removed

- The libdnf5 actions plugin (`/etc/dnf/libdnf5-plugins/actions.d/atomic-rollback.actions`) is no longer shipped. The RPM C plugin added in 0.3.7 covers every RPM-based frontend (dnf, rpm, PackageKit); keeping both caused duplicate snapshots on dnf5 transactions. Closes #16.

### Fixed

- Systems upgrading from any 0.3.x release have their legacy `root.pre-update` snapshot renamed to its creation timestamp (in the same `%Y-%m-%d_%H-%M-%S` format as new automatic snapshots) on upgrade. The renamed snapshot joins the rolling history and becomes eligible for retention; before this release it did not match the auto-name format and was treated as a user-named snapshot, persisting indefinitely on upgraded systems. The btrfs subvolume ID is preserved across the rename, so rollback targets that referenced the numeric ID are unaffected.

## [0.3.8] - 2026-04-07

### Fixed

- `check`, `setup`, and `migrate` failed at the baseline gate with "Btrfs subvolume 'root' not found" on systems with a non-default root subvolume name (e.g., the openSUSE Timeshift `@` layout). The root filesystem check hardcoded `"root"` instead of reading the `subvol=` mount option from `/etc/fstab`. Closes #15.

## [0.3.7] - 2026-04-05

### Added

- RPM plugin: snapshots are now created before every RPM transaction regardless of frontend (dnf, PackageKit/Discover, bare rpm). Previously only dnf5 transactions triggered snapshots via the libdnf5 actions plugin.

### Fixed

- `snapshot` no longer prints contradictory "already exists" and "created" messages on the same call. The function returns a typed result and the caller handles messaging.
- `snapshot` is now a safe no-op on non-btrfs systems instead of failing and blocking package transactions.

## [0.3.6] - 2026-04-04

### Fixed

- `check`, `setup`, and `migrate` failed on aarch64 with "shimx64.efi is missing." The EFI boot file check hardcoded x86_64 filenames instead of deriving them from the UEFI architecture suffix.

## [0.3.5] - 2026-04-03

### Changed

- All device references are now typed. Bare UUIDs, fstab device specs (UUID=, LABEL=, PARTUUID=, PARTLABEL=, ID=, /dev/ paths), resolved device paths, and subvolume names each have distinct types. Passing a bare UUID where a device spec is expected (the bug fixed in 0.3.3) is now a compile error. No behavior changes.

## [0.3.4] - 2026-04-03

### Changed

- License changed from MIT OR Apache-2.0 to GPL-3.0-only. All future versions of this project are licensed under the GNU General Public License v3.0 only. Previously published versions (0.3.3 and earlier) remain under their original license. See LICENSE for the full text.

### Removed

- `scripts/monitor-reddit.sh` (one-time utility, not part of the distributed package).

## [0.3.3] - 2026-04-03

### Fixed

- `check` failed on vanilla Fedora 43 with "Can't lookup blockdev." The root UUID extracted from BLS boot entries was passed to mount without the `UUID=` prefix, so mount received a bare UUID string instead of a valid device spec. All stock Fedora installs using `UUID=` in fstab were affected.

## [0.3.2] - 2026-04-01

### Changed

- Internal architecture: all external tool output parsed through grammar-derived types at the boundary. Filesystem type comparisons use an enum instead of string matching.

### Fixed

- Subvolume names with spaces now parse correctly. The btrfs output parser used whitespace splitting which truncated paths containing spaces.
- Verification chain now handles all fstab device formats (PARTUUID=, PARTLABEL=, ID=). Previously only UUID= entries were verified; other formats silently passed without checking.
- BLS initrd validation checks all initrd lines. The verified parser previously returned only the first match; entries with multiple initrd lines had subsequent lines unchecked.
- BLS root= parameter check accepts all kernel device formats (PARTUUID=, PARTLABEL=, /dev/). Previously only root=UUID= and root=/dev/ were accepted.
- ESP grub.cfg migration renders from the generator template instead of line surgery, eliminating the double-prefix bug class by construction.

## [0.3.1] - 2026-03-31

### Changed

- Installation via COPR is the only supported method. The crate was removed from crates.io (binary alone is insufficient without the hook and plugin).

### Fixed

- Kernel-install hook uses full binary path (/usr/bin/atomic-rollback). The bare command was not in RPM's scriptlet PATH, causing exit 127 on kernel upgrades.
- RPM spec rewritten for COPR vendored builds. The previous spec used %cargo_build which expects Fedora-packaged crates.
- COPR Makefile builds from cloned source with correct outdir contract.

## [0.3.0] - 2026-03-30

### Added

- `snapshot create [name]` subcommand: explicit snapshot creation with optional name.
- `snapshot list` subcommand: shows available snapshots, excluding system subvolumes.
- `snapshot delete <name>` subcommand: refuses fstab-referenced system subvolumes (verified in VM that btrfs-progs does not check fstab). Mounted-subvolume and default-subvolume protection delegated to kernel and btrfs-progs respectively.
- `--help` and `-h` at top level and for snapshot subcommands.

### Changed

- `snapshot <name>` replaced by `snapshot create <name>`. Bare `snapshot` (no args) still creates with the default name. Unrecognized snapshot subcommands are now rejected instead of silently treated as snapshot names.

### Fixed

- Migration step 1 now handles all fstab device reference formats (UUID=, LABEL=, /dev/ paths). Previously only UUID= was supported.

## [0.2.0] - 2026-03-29

### Added

- `setup` command: separates /var and enables root snapshots and rollback without touching /boot or the ESP. Works on stock Fedora partition layout. No GRUB Btrfs dependency. Closes #1.
- 12th Kani theorem (`setup_is_safe`): setup preserves bootability, is reboot-safe after sync, data-safe, and rollback works on the setup'd system.

## [0.1.4] - 2026-03-29

### Added

- 11th Kani theorem (`data_safe_across_all_operations`): /home and /var are never modified by any operation (separate subvolumes, not part of any swap). After rollback, the old root is preserved at the snapshot name. No operation in the tool destroys user data.

### Fixed

- ESP grub.cfg substitution now verifies all three model properties (UUID, `btrfs_relative_path`, prefix path) on the output BEFORE the swap. Previously only the UUID was checked. If any property is missing, the swap is refused and the old ESP is preserved. Closes the gap that allowed prefix doubling to reach the swap during development.

## [0.1.3] - 2026-03-29

### Added

- `syncfs` at every exit point (migration, rollback, kernel hook). Btrfs `RENAME_EXCHANGE` and `set-default` use `btrfs_end_transaction` (in-memory journal only). Without `syncfs`, changes could be lost on power failure within 30 seconds of completion. Derived from kernel source (inode.c:8534, ioctl.c:2806).
- 10th Kani theorem (`all_exit_points_are_reboot_safe`): every exit point is both bootable AND durable. The model tracks `durable: bool` and requires `sync_filesystem` before `reboot_safe` can hold.

## [0.1.1] - 2026-03-29

### Added

- `check`, `migrate`, `rollback`, `snapshot` commands.
- 10-step gated migration: /boot to Btrfs, /var separation, ESP update, grubenv NOCOW, save_env stripping, symlinks, kernel-install hook.
- 9 Kani-verified theorems: migration preserves bootability, rollback preserves bootability, step ordering, kernel installs, idempotency, GRUB Btrfs constraint, creation failure safety, all swaps require verification, /var config consistency.
- 15 Verus-verified parser conditions inline via `verus!` macro.
- Verify-before-swap for all `RENAME_EXCHANGE` operations (rollback, migration, kernel hook).
- Rollback undoes swap if `set-default` fails.
- `WARN` output for partially valid boot entries (exit code 2).
- `platform.rs` centralizes distro-specific paths.
- `dnf` plugin for automatic pre-transaction snapshots via libdnf5 actions.
- Idempotent snapshot command (existing snapshot returns success).
- `resolve_fstab_device` handles `UUID=`, `/dev/`, `LABEL=`.
- All system-specific values (device ref, compression, subvol name) derived from fstab.
- Bootability predicate derived from the actual Fedora boot chain.
- RPM spec with kernel-install hook and dnf plugin.

