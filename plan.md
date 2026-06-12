# dm-verity RootFS Protection Implementation Plan

## Goal

Implement a minimal device-mapper framework and a read-only `verity` target in Asterinas so a root filesystem can be mounted from a verified virtual block device such as `/dev/dm-0`.

Target boot command line:

```text
root=/dev/dm-0 rootfstype=ext2 ro \
dm_mod.create="vm_verity,,,ro,0 512000 verity 1 /dev/vda1 /dev/vda2 4096 4096 64000 0 sha256 <root_hash> <salt>"
```

The first deliverable should focus on correctness and boot viability rather than full Linux `dmsetup` compatibility.

## Status Update

As of 2026-06-12, the implementation status against this plan is:

- Milestone 0 is complete for the current accepted deliverable: there is an opt-in initramfs-assisted verified-root bootstrap for `root=/dev/... rootfstype=ext2` that mounts the requested block root under an internal mountpoint, resolves init from that mounted root, and chroots the first process into it. The direct kernel-driven `root=` path is now tracked as a separate follow-on goal.
- Milestone 1 is complete for the first bring-up: the `kernel/comps/dm` component exists, `DmDevice` is registered through `aster_block`, stable `/dev/dm-<minor>` naming is used, logical names are preserved internally, table lookup is implemented, and read-only policy is enforced.
- Milestone 2 is complete for the initial single-table-entry flow: `dm_mod.create` is registered through the kernel command-line framework, the expected `verity` table syntax is parsed and validated, block devices are resolved during first-kthread realization, and malformed inputs fail during validation.
- Milestone 3 is partially complete: the `verity` target now validates reads against a SHA-256 hash tree, rejects writes, supports multi-block and unaligned reads, and maintains a small in-memory hash-block cache. A frozen Linux `veritysetup` vector plus refresh/check workflow are documented, but broader compatibility validation against additional Linux/`veritysetup` vectors is still pending.
- Milestone 4 is complete for the current initramfs-assisted deliverable: an opt-in bootstrap can mount an ext2 block root before init is spawned, propagate `/dev` into the new root, switch the first process into it, and boot a maintained dm-verity-protected sample rootfs through `root=/dev/dm-0`. Direct kernel-driven `root=` block-root activation is now tracked as a separate follow-on goal, while broader filesystem support remains future work.

### Execution Board

| Milestone | Status | Completed | Remaining | Next Gate |
|-----------|--------|-----------|-----------|-----------|
| 0. Activation path | Complete | The codebase now has an opt-in initramfs-assisted verified-root bootstrap path for `root=/dev/... rootfstype=ext2`, and that path has been validated end to end with a maintained dm-verity-protected sample root image while preserving the existing initramfs-only default flow. | No remaining work for the accepted initramfs-assisted deliverable. | Keep the accepted boundary explicit while follow-on work proceeds separately. |
| 1. Device-mapper core | Complete | `DmDevice`, table lookup, target dispatch, stable `/dev/dm-*` naming, and read-only rejection are in place. | No blocking core work for the first bring-up. Only follow-up refactors if later milestones expose design pressure. | Keep the current APIs stable while later milestones validate them. |
| 2. `dm_mod.create` parser | Complete | Single-entry parser, validation, deferred device resolution, and malformed-input rejection are in place. | Multi-entry tables and broader syntax compatibility remain intentionally out of scope for now. | The parser must stay stable while compatibility vectors are added. |
| 3. Read-only `verity` target | In progress | Verified reads, write rejection, unaligned reads, multi-block reads, a small hash-block cache, and a documented frozen-vector workflow are implemented. | Add broader Linux `veritysetup` compatibility validation, more fixed vectors, and stronger negative coverage around layout assumptions. | The current workflow must remain sufficient to refresh and validate the frozen fixture. |
| 4. Verified root activation | Complete | An opt-in initramfs-assisted bootstrap can now recognize `root=` / `rootfstype=ext2`, mount the selected block root at an internal bootstrap mountpoint before init is spawned, resolve init from that mounted root, bind-mount `/dev` into the new root, and chroot the first process into it. A maintained verified ext2 root image now boots end to end through `root=/dev/dm-0`. | No remaining work for the accepted initramfs-assisted deliverable. | Keep regressions green while follow-on direct-root work proceeds separately. |
| 5. Image and validation tooling | In progress | The repository now has documented refresh/check workflow, sample image-generation guidance, an emitted `dm_mod.create` fragment, emitted Linux-compatible boot-argument examples, an opt-in Makefile helper for passing a caller-supplied `dm_mod.create` fragment into boot, a sample helper that attaches the maintained dm-verity vector as extra boot disks, a bootable verified ext2 root sample generator, and explicit opt-in boot-validation targets for both the maintained vector and the maintained root sample. | Keep the external parameter format Linux-compatible while limiting current integration to opt-in Asterinas helpers; keep automated QEMU/OSDK activation explicit rather than folding it into default boot flows. | A documented workflow can regenerate the maintained vector, the maintained bootable root sample, the emitted `dm_mod.create` fragments, and both opt-in boot validation runs. |
| 6. Tests | In progress | Unit coverage now includes basic geometry, happy-path reads, corruption failures, a frozen-vector regression for hash-block padding semantics, fixed Linux `veritysetup` vectors for the single-block/no-hash-block, two-block/one-hash-block, three-block/one-hash-block, four-block/one-hash-block, five-block/one-hash-block, six-block/one-hash-block, seven-block/one-hash-block, eight-block/one-hash-block, nine-block/one-hash-block, ten-block/one-hash-block, eleven-block/one-hash-block, twelve-block/one-hash-block, thirteen-block/one-hash-block, fourteen-block/one-hash-block, fifteen-block/one-hash-block, and sixteen-block/one-hash-block cases, plus external offset and wrong-salt regressions built from fixed Linux vectors. Boot-level coverage now includes an opt-in initramfs harness on the maintained sample path that verifies `/dev/dm-0` end to end. | Add more fixed compatibility vectors beyond the first sixteen external cases if later milestones need them. | Focused tests must validate external assumptions rather than only self-generated trees. |
| 7. Documentation | In progress | The kernel parameter docs now describe the supported `dm_mod.create` syntax, the frozen dm-verity fixture refresh/check workflow, current bootable-sample guidance, and the current verified-root activation boundary. | Add any deeper follow-up docs only if later milestones expand the supported workflow. | Documentation must stay aligned with the maintained workflow and current implementation limits. |

### Documentation Slice

- Subtask 7A: Document the currently supported `dm_mod.create` syntax and limits. Complete.
- Subtask 7B: Document the frozen dm-verity fixture refresh/check workflow. Complete.
- Subtask 7C1: Document the current unsupported-feature and boot-activation limitations. Complete.
- Subtask 7C2: Document broader image-generation guidance. Complete for the maintained sample fixture.
- Subtask 7C3: Document future root-activation guidance. Complete.

### Tooling Slice

- Subtask 5A: Emit a reusable `dm_mod.create` fragment from the maintained sample generator. Complete.
- Subtask 5B: Emit reusable boot-argument examples from the maintained sample generator. Complete.
- Subtask 5C1: Add a Makefile-level passthrough for optional extra kernel command-line arguments into cargo-osdk run/build. Complete.
- Subtask 5C2A: Add an opt-in Makefile helper that threads a caller-supplied `dm_mod.create` fragment into `EXTRA_KCMD_ARGS` without changing default boot flows. Complete.
- Subtask 5C2B1: Emit an opt-in helper invocation example that keeps Linux-compatible `dm_mod.create` formatting while leaving device placeholders under caller control. Complete.
- Subtask 5C2B2: Thread the maintained dm-verity sample boot-arg fragment into an opt-in boot helper once a concrete sample device layout is wired into the boot environment. Complete.
- Subtask 5C3: Add an explicit opt-in boot-validation target that drives the maintained sample through QEMU/OSDK without changing default boot flows. Complete.

### Test Slice

- Subtask 6C1: Add a frozen-vector regression for hash-block padding semantics. Complete.
- Subtask 6C2A: Add a fixed Linux `veritysetup` vector for the single-block/no-hash-block case. Complete.
- Subtask 6C2B1: Add a fixed Linux `veritysetup` vector for the two-block/one-hash-block case. Complete.
- Subtask 6C2B2A: Add an external `hash_start_block` offset check based on a fixed Linux `veritysetup` vector. Complete.
- Subtask 6C2B2B1: Add an external wrong-salt regression based on a fixed Linux `veritysetup` vector. Complete.
- Subtask 6C2B2B2A: Add a fixed Linux `veritysetup` vector for the three-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B1: Add a fixed Linux `veritysetup` vector for the four-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2A: Add a fixed Linux `veritysetup` vector for the five-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the six-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2A: Add a fixed Linux `veritysetup` vector for the seven-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the eight-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2A: Add a fixed Linux `veritysetup` vector for the nine-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B: Add more fixed Linux `veritysetup` compatibility vectors beyond the first nine external cases. In progress.
- Subtask 6C2B2B2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the ten-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2: Add more fixed Linux `veritysetup` compatibility vectors beyond the first ten external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2A: Add a fixed Linux `veritysetup` vector for the eleven-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B: Add more fixed Linux `veritysetup` compatibility vectors beyond the first eleven external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the twelve-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B2: Add more fixed Linux `veritysetup` compatibility vectors beyond the first twelve external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2B2A: Add a fixed Linux `veritysetup` vector for the thirteen-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B2B: Add more fixed Linux `veritysetup` compatibility vectors beyond the first thirteen external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the fourteen-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B2B2: Add more fixed Linux `veritysetup` compatibility vectors beyond the first fourteen external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2B2B2A: Add a fixed Linux `veritysetup` vector for the fifteen-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B2B2B: Add more fixed Linux `veritysetup` compatibility vectors beyond the first fifteen external cases. In progress.
- Subtask 6C2B2B2B2B2B2B2B2B2B1: Add a fixed Linux `veritysetup` vector for the sixteen-block/one-hash-block case. Complete.
- Subtask 6C2B2B2B2B2B2B2B2B2B2: Add more fixed Linux `veritysetup` compatibility vectors beyond the first sixteen external cases. Pending.
- Subtask 6C3A: Add an opt-in boot-level dm-verity harness that boots the maintained sample on a viable command-line transport path and probes `/dev/dm-0` from initramfs. Complete.
- Subtask 6C3B: Resolve the remaining boot-time hang on the first verified read from `/dev/dm-0` so the boot-level regression can pass end to end. Complete.

### Current Deliverable Boundary

The current codebase can create `/dev/dm-0`-style devices from `dm_mod.create`, route `linear` requests, perform read-only `verity` verification in-kernel, exercise the maintained tiny sample through an opt-in boot-level initramfs regression, and boot a maintained dm-verity-protected ext2 rootfs through the opt-in initramfs-assisted `root=/dev/dm-0 rootfstype=ext2 ro` path. The direct kernel-driven root-mount path is now a separate follow-on goal rather than part of the accepted current deliverable.

## Current Repository Facts

- The block layer exposes a simple `BlockDevice` trait with `enqueue`, `metadata`, `name`, and `id` methods.
- Block devices can be registered globally and are exposed through devtmpfs.
- Partition support already demonstrates simple logical-to-physical sector remapping with `SubmittedBio::set_sid_offset`.
- The kernel command-line framework supports registered key-value and flag parameters.
- For OSTD-based kernel crates, focused single-crate tests should be run from the crate directory with `cargo osdk test`, for example `cd kernel/comps/dm && cargo osdk test ten_block_frozen_verity_vector_matches_linux_veritysetup`; bare `cargo test` uses the host target and can miss `ostd`'s `x86_64-unknown-none` target-specific dependencies.
- The default root filesystem path is still initramfs-first, but there is now an opt-in initramfs-assisted verified-root bootstrap for `root=/dev/... rootfstype=ext2`, and it has been validated end to end with a maintained dm-verity-protected ext2 sample rootfs. A direct kernel-driven `root=` block device boot path is still not present.
- The repository currently has ext2 support. The ext2 implementation states that ext3/ext4 extensions are not included.
- No existing SHA-256 digest dependency was found in the workspace search; a digest implementation or dependency will likely be needed.

## Scope

### In Scope

- A kernel-internal device-mapper framework.
- A read-only `verity` target.
- Kernel command-line parsing for `dm_mod.create`.
- Creation of `/dev/dm-0` style virtual block devices during boot.
- Read-only routing and verification of root filesystem reads.
- Basic `root=`, `rootfstype=`, and `ro` boot integration, if direct block-root boot is selected for the milestone.
- Tests for table parsing, I/O routing, verification success, verification failure, and read-only behavior.

### Out of Scope for the First Milestone

- Full Linux `dmsetup` or libdevmapper ioctl compatibility.
- Dynamic runtime table reload through userspace.
- Writable device-mapper targets.
- Advanced targets such as `crypt`, `thin`, `snapshot`, `stripe`, or `mirror`.
- Discard, write-zeroes, or flush semantics beyond the minimal read-only verity requirement.
- TDX attestation and Trustee/KBS policy integration. The root hash should be structured so that this can be added later.
- Full ext4 support, unless that is made a separate filesystem milestone.

## Milestone 0: Decide the Boot Strategy

### Option A: Initramfs-Assisted Boot

Use initramfs to create or trigger the verified device, mount it, and pivot into it. This requires less kernel boot-chain work and is the recommended first path if the goal is to prove dm-verity protection quickly.

Estimated new code: 2,600 to 4,100 lines total.

### Option B: Kernel-Driven `root=` Boot

The kernel parses `dm_mod.create`, creates `/dev/dm-0`, resolves `root=/dev/dm-0`, mounts `rootfstype`, and starts init from the verified block root.

Estimated new code: 3,000 to 5,000 lines total.

### Tasks

- Choose Option A or Option B as the first deliverable.
- Decide whether the initial filesystem image will be ext2 or ext4.
- Decide whether `rootfstype=ext4` is a strict requirement for the first milestone. If yes, create a separate ext4 support plan.

### Deliverables

- Written decision on the boot strategy.
- Written decision on the filesystem type for the first verified root image.

## Milestone 1: Device-Mapper Core

Estimated new code: 400 to 700 lines.

### Tasks

- Add a new device-mapper module or component, for example `kernel/comps/dm` or `kernel/src/device/mapper`, following the repository's component boundaries.
- Define a `DmDevice` type implementing `aster_block::BlockDevice`.
- Define a mapping table representation:
  - device name;
  - device flags such as read-only;
  - one or more table entries;
  - logical start sector;
  - logical sector count;
  - target name;
  - target-specific parameters.
- Define a `DmTarget` trait for registered targets.
- Implement a target registry keyed by target name, initially containing `verity`.
- Implement mapping lookup from logical sector range to target entry.
- Implement virtual block-device metadata using the mapped table size.
- Allocate stable device IDs for `/dev/dm-*` devices.
- Register newly created mapper devices through `aster_block::register`.
- Generate deterministic names such as `dm-0`, while preserving the configured logical name such as `vm_verity` internally.
- Enforce read-only policy at the device-mapper layer.

### Deliverables

- `DmDevice` can be registered as a block device.
- `/dev/dm-0` is created through the existing device/devtmpfs path.
- A read request can be routed to a target implementation.
- Write requests to a read-only mapper return an error.

### Risks

- Device unregister and devtmpfs node removal are currently incomplete. Avoid runtime removal in the first milestone.
- Existing block-device registry and device registry are separate; avoid adding another duplicate registry unless necessary.

## Milestone 2: `dm_mod.create` Parser

Estimated new code: 250 to 450 lines.

### Tasks

- Register `dm_mod.create` with the kernel command-line framework as a key-value or repeatable key-value parameter.
- Implement a parser for the expected format:

```text
<name>,<uuid>,<minor>,<flags>,<table>
```

- Support the initial table format:

```text
<start_sector> <num_sectors> verity <version> <data_dev> <hash_dev> \
<data_block_size> <hash_block_size> <num_data_blocks> <hash_start_block> \
<hash_algorithm> <root_hash> <salt>
```

- Parse and validate device name, flags, sector ranges, target name, verity version, devices, block sizes, data block count, hash start block, hash algorithm, root hash, and salt.
- Resolve `/dev/vda1` and `/dev/vda2` into registered block devices.
- Delay device resolution until device nodes and block devices are available, if command-line parsing runs earlier than block-device registration.
- Add clear error messages for malformed tables.

### Deliverables

- The sample `dm_mod.create` string parses into a validated in-kernel table.
- Invalid strings fail early with useful diagnostics.
- The parsed table can instantiate a `DmDevice`.

### Risks

- The command-line framework parses parameters early. Block devices may not be available until later initialization stages, so parsing and realization may need to be separate steps.
- Quoting behavior for long `dm_mod.create` values must be tested with the boot loader and QEMU command line.

## Milestone 3: Read-Only `verity` Target

Estimated new code: 550 to 950 lines.

### Tasks

- Add a `VerityTarget` implementing the `DmTarget` trait.
- Define a validated `VerityConfig` containing version, data device, hash device, data block size, hash block size, protected data block count, hash start block, hash algorithm, root hash, and salt.
- Add or import a no-std-compatible SHA-256 implementation.
- Define a digest abstraction so that only `sha256` is supported initially but future algorithms can be added cleanly.
- Implement dm-verity hash layout calculation:
  - digest size;
  - hashes per hash block;
  - number of levels;
  - block index at each level;
  - hash block location relative to `hash_start_block`.
- Implement verified reads:
  - reject writes;
  - read the requested data block from the data device;
  - read required hash blocks from the hash device;
  - hash with the exact dm-verity-compatible salt and block ordering selected;
  - compare each level up to the trusted root hash;
  - copy verified data to the caller's BIO segment only after verification.
- Handle reads spanning multiple verity data blocks.
- Handle reads whose sector range is not aligned to the verity data block size.
- Cache verified hash blocks or verified data block hashes to avoid excessive hash-device reads.
- Return I/O errors on verification failure.
- Add counters or debug logs for verification failures and cache hits if useful.

### Deliverables

- Reads from an unmodified verity image succeed.
- Reads from a corrupted data block fail.
- Reads from a corrupted hash block fail.
- Writes always fail on the verity target.

### Risks

- The exact hash input ordering must match the userspace image builder. Linux dm-verity compatibility should be validated with known test vectors.
- Current BIO operations are limited to read, write, and flush. That is enough for a read-only verity target but limits broader device-mapper compatibility.
- A naive implementation may reread too many hash blocks and be slow during boot. Add at least a small hash-block cache.

## Milestone 4: Root Device Boot Integration

Estimated new code: 350 to 800 lines for basic root boot plumbing, excluding filesystem work.

### Tasks

- Register and parse `root=<path>`, `rootfstype=<type>`, `ro`, and optionally `rw` for explicit rejection or future support.
- Decide the initialization stage where dm devices are realized: after physical block devices and partitions exist, but before the root filesystem is mounted.
- Add a block-root mount path if using kernel-driven boot:
  - resolve `root` to a block device path;
  - look up `rootfstype` in the VFS filesystem registry;
  - create a filesystem instance backed by the block device;
  - mount it as the root or pivot from initramfs root;
  - pass read-only mount flags when `ro` is present.
- Keep the current initramfs path working for existing boot flows.
- Define fallback behavior if `root=` is missing or dm device creation fails.
- Ensure `/dev` is mounted or otherwise available early enough for path-based device resolution, or support direct device lookup by name before devtmpfs.

### Deliverables

- Boot can create `/dev/dm-0` from `dm_mod.create`.
- Boot can mount the selected root device read-only if the selected filesystem is supported.
- The initramfs-assisted verified-root path can propagate `/dev` into the new root and start `/init` from that root.
- Existing initramfs-only boot still works.

### Risks

- Current rootfs setup is initramfs-first. Kernel-driven block root requires careful ordering changes.
- If `rootfstype=ext4` is mandatory, this milestone depends on separate ext4 filesystem support.

## Follow-on Goal: Direct Kernel-Driven Root Path

This follow-on goal is intentionally separate from the accepted initramfs-assisted verified-root deliverable. It tracks the stricter path where the kernel mounts the verified block root as the real root directly, instead of pivoting from an initramfs-assisted bootstrap.

Estimated new code: 250 to 700 lines, excluding any broader filesystem enablement.

### Tasks

- Mount the verified block root as the real root without relying on an initramfs-assisted bootstrap handoff.
- Revisit early boot ordering so the selected root device, filesystem instance, and mount namespace are ready before init resolution.
- Decide whether `/dev` path resolution remains path-based or moves fully to direct device lookup before devtmpfs is available.
- Preserve the current default initramfs-only boot flow and the accepted initramfs-assisted verified-root flow while adding the direct-root path as an explicit opt-in mode.
- Define fallback behavior when direct root activation fails after `dm_mod.create` succeeds.

### Deliverables

- An opt-in direct kernel-driven `root=/dev/dm-0` activation path exists in addition to the current initramfs-assisted path.
- The kernel can resolve init and start userspace without relying on the initramfs-assisted root handoff.
- Existing initramfs-only boot and accepted initramfs-assisted verified-root boot both still work.

### Risks

- Early boot ordering is tighter here than in the initramfs-assisted design and may force changes near init resolution, mount namespace setup, or device discovery.
- If broader filesystem coverage is required, this goal may depend on separate filesystem work beyond the current ext2-only path.

## Milestone 5: Image and Build Tooling

Estimated new code: 120 to 250 lines.

### Tasks

- Add a script or documented command to create the root filesystem image, the dm-verity hash image, the root hash, and the salt.
- Decide whether to use Linux `veritysetup` or a repository-local tool for image generation.
- Add opt-in Makefile or OSDK wiring to pass Linux-compatible `dm_mod.create`, and later `root`, `rootfstype`, and `ro`, to the kernel without changing default boot flows.
- Document how to reproduce the image and invoke the opt-in helper or boot arguments.
- Store test vectors for a small verity image.

### Deliverables

- A reproducible command sequence builds a verity-protected root image.
- The generated root hash and salt can be inserted into the boot command line.
- A corrupted image can be generated for negative tests.

### Risks

- Linux dm-verity image layout details must match the kernel implementation.
- Linux-compatible command lines may still need Asterinas-specific helper wrapping and quoting fixes in tooling.

## Milestone 6: Tests

Estimated new code: 950 to 1,500 lines.

### Unit and Kernel Tests

- Parse valid `dm_mod.create` values.
- Reject malformed `dm_mod.create` values.
- Validate mapper table range lookup.
- Validate read-only write rejection.
- Validate verity tree geometry calculation.
- Verify known dm-verity test vectors.
- Fail reads with bad root hash.
- Fail reads with corrupted data block.
- Fail reads with corrupted hash block.
- Verify reads spanning multiple data blocks.
- Verify partial-sector or unaligned read behavior according to the chosen block-layer policy.

### Integration Tests

- Boot with valid `dm_mod.create` and mount the verified root device.
- Boot with a corrupted rootfs data block and confirm mount or read fails.
- Boot with a corrupted hash device and confirm mount or read fails.
- Confirm raw data device is not mounted as root when `root=/dev/dm-0` is set.

### Deliverables

- Focused kernel tests for parser, mapper core, and verity target.
- At least one boot-level regression test.

## Milestone 7: Documentation

Estimated new code: 130 to 250 lines.

### Tasks

- Document supported `dm_mod.create` syntax.
- Document unsupported Linux device-mapper features.
- Document the verity hash format and assumptions.
- Document the image generation flow.
- Document how the root hash will later be bound to TDX attestation and Trustee/KBS policy.

### Deliverables

- A developer-facing guide for creating and booting a verified rootfs.
- A short limitation section for unsupported device-mapper features.

## Suggested Implementation Order

1. Add dm-core skeleton and a fake passthrough target for testing.
2. Add `dm_mod.create` parsing for one device and one table entry.
3. Register `/dev/dm-0` from boot parameters.
4. Replace the fake target with `verity` read verification.
5. Add image generation tooling and known test vectors.
6. Add initramfs-assisted boot integration.
7. Add kernel-driven `root=` boot only after the verified block device is stable.
8. Add performance cache and broader negative tests.

## Estimated Code Size

These revised ranges assume continued reuse of the existing block-device registration,
kernel command-line parsing, devtmpfs exposure, and initramfs-first boot
infrastructure instead of building parallel subsystems for dm-verity.

| Area | Estimated Lines |
|------|-----------------|
| Device-mapper core | 400 - 700 |
| `dm_mod.create` parser | 250 - 450 |
| `verity` target | 550 - 950 |
| Root boot integration | 350 - 800 |
| Image/build tooling | 120 - 250 |
| Tests | 950 - 1,500 |
| Documentation | 130 - 250 |
| Total, initramfs-assisted | 2,600 - 4,100 |
| Total, kernel-driven root boot | 3,000 - 5,000 |

## Acceptance Criteria

- A boot command line can describe one read-only verity mapper device.
- The kernel creates a virtual block device such as `/dev/dm-0`.
- Reads through `/dev/dm-0` verify data against the hash device and trusted root hash.
- Writes through `/dev/dm-0` fail.
- Corruption in the data device or hash device is detected.
- The verified device can be used as the root filesystem through the selected boot strategy.
- Existing non-dm boot paths continue to work.

## Open Questions

- Should the first root filesystem image use ext2 instead of ext4 to avoid adding ext4 support to this milestone?
- Should the first milestone use initramfs-assisted boot or kernel-driven `root=` boot?
- Should the verity layout aim for strict Linux dm-verity compatibility from day one, or only compatibility with the repository's image generation tooling?
- Which no-std SHA-256 implementation should be used?
- How should root hash trust be represented before TDX attestation and Trustee/KBS integration are added?
