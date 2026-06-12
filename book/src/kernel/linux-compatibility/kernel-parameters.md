# Kernel Parameters

This section documents kernel command-line parameters supported by Asterinas.

## Inherited from Linux

### `init`

Run the specified binary as `init`.

Example:
```text
init=/bin/busybox
```

Notes:
- The value is the path to the executable.
- If omitted, Asterinas will try to execute from the following paths in order:
  `/sbin/init`, `/etc/init`, `/bin/init`, `/bin/sh`.

### `console`

Select console devices for kernel messages.
This parameter may be specified multiple times.
Kernel messages are delivered to each listed console.

Valid values:
- `tty0`
- `ttyS0`
- `hvc0`

Examples:
```text
console=ttyS0
console=ttyS0 console=hvc0
```

## Asterinas-specific

### `ostd.log_level`

Set the verbosity level for Asterinas's logs.

Valid values (from most to least severe):
- `off`
- `emerg`
- `alert`
- `crit`
- `error`
- `warn` (alias: `warning`)
- `notice`
- `info`
- `debug`

Example:
```text
ostd.log_level=error
```

### `i8042.exist`

Override ACPI's indication of whether a PS/2 (i8042) controller exists.

Valid values:
- `1`, `on`, `yes`, `true` or no value — treat the i8042 controller as present (force probing)
- `0`, `off`, `no`, `false` - treat the i8042 controller as absent (skip probing)

Examples:
```text
i8042.exist
i8042.exist=1
i8042.exist=0
```

### `dm-mod.create`

Create a device-mapper block device during boot.
This parameter may be specified multiple times.

Supported top-level syntax:
```text
dm-mod.create=<name>,<uuid>,<minor>,<flags>,<table>
```

Current supported table forms:
```text
<start_sector> <num_sectors> linear <device_path> <physical_start>
<start_sector> <num_sectors> verity <version> <data_dev> <hash_dev> \
<data_block_size> <hash_block_size> <num_data_blocks> <hash_start_block> \
<hash_algorithm> <root_hash> <salt>
```

Current implementation notes:
- Only a single table entry is supported per device.
- Supported target names are `linear` and `verity`.
- The only supported device flag is `ro`.
- Empty `uuid` and `minor` fields are allowed.
- `root_hash` and `salt` must be even-length hexadecimal strings.
- The current single-entry validation requires the first logical sector to be `0`.
- The verity implementation currently supports `sha256` only.
- Boot-time mapper creation is supported, but direct `root=/dev/dm-*` activation is not implemented yet.

Example:
```text
dm-mod.create="vm_verity,,,ro,0 512000 verity 1 /dev/vda1 /dev/vda2 4096 4096 64000 0 sha256 <root_hash> <salt>"
```

Developer workflow for the frozen dm-verity fixture:
- Run `make refresh_verity_test_vector` to regenerate the sample data image, hash image, and root hash under `target/verity-vector/`.
- Run `make check_verity_test_vector` to compare the generated output against the frozen fixture used by the kernel tests.
- Both targets require `veritysetup` and `python3` to be available in the environment.


Current limitations:
- Multi-entry device-mapper tables are not supported yet.
- Runtime table reload, device removal, and `dmsetup` ioctl compatibility are out of scope.
- The `verity` target is read-only; writable targets are not implemented.
- The current compatibility workflow validates one frozen Linux `veritysetup` vector, not a broader matrix of generated images.
- Direct `root=/dev/dm-*` activation is still a follow-on milestone; the current boot flow remains initramfs-first.
- ext4 rootfs activation is not part of the current dm-verity deliverable; the repository's existing filesystem support remains the practical constraint.


Image-generation guidance for the maintained sample fixture:
- Run `make refresh_verity_test_vector` to populate `target/verity-vector/data.img`, `target/verity-vector/hash.img`, and `target/verity-vector/root_hash.txt`.
- The generated sample image contains three 4096-byte data blocks with `verity-block-000`, `verity-block-001`, and `verity-block-002` prefixes.
- The maintained sample uses `veritysetup format --no-superblock --format=1 --hash=sha256 --data-block-size=4096 --hash-block-size=4096 --data-blocks=3 --salt=73616c74`.
- Use the contents of `target/verity-vector/root_hash.txt` as the `root_hash` field in `dm-mod.create` when reproducing the sample configuration.
- Use `target/verity-vector/hash.img` as the hash device payload and `target/verity-vector/data.img` as the data device payload when building or refreshing tests around the frozen fixture.
- The generator now prints a ready-to-edit `dm-mod.create` fragment with the generated `root_hash`; replace `<data_dev>` and `<hash_dev>` with the block-device paths for your setup.
- The generator also prints a mapper-only boot-argument example for the currently supported workflow, plus a separately labeled future direct-root example that remains unsupported until root-device boot integration lands.


Future root-activation guidance:
- The current boot flow is still initramfs-first, so treat `dm-mod.create` today as mapper bring-up rather than as a complete `root=/dev/dm-*` solution.
- A future direct-root path will need to realize physical block devices, partitions, and dm devices before resolving `root=` and `rootfstype=`.
- If direct root activation is added, prefer boot arguments that keep the verified device read-only, for example `root=/dev/dm-0 ro`, and pair them with a filesystem type that Asterinas can actually mount.
- If the eventual activation path remains initramfs-assisted, the expected workflow is to create or validate `/dev/dm-0` from early userspace and then switch root with the existing mount/pivot machinery.
- The current sample fixture is suitable for mapper validation and compatibility checks, but not yet as a drop-in verified rootfs image.
