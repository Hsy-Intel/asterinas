#!/bin/sh
set -eu

usage() {
    cat <<'EOF'
Usage: ./tools/generate_verity_test_vector.sh [--check] [out_dir]

Builds the sample dm-verity vector in out_dir (default: ./target/verity-vector).
With --check, compares the generated root hash and hash image against the frozen
fixture used by the kernel dm-verity tests.
EOF
}

mode=generate
case "${1:-}" in
    --check)
        mode=check
        shift
        ;;
    --help|-h)
        usage
        exit 0
        ;;
esac

if [ "$#" -gt 1 ]; then
    usage >&2
    exit 2
fi

if ! command -v veritysetup >/dev/null 2>&1; then
    echo "veritysetup is required to generate dm-verity compatibility vectors" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required to build the sample data image" >&2
    exit 1
fi

expected_root_hash=71caa9632cfdd78bd94b03198ba93cefb8ad7babc510e357028e8d167ba16a47
expected_hash_prefix_hex=$(printf '%s'     4a4bc0f86f12a8f082b3eacd6d098fa5225bd02486979375c577a8f3c55f6773     dbe8caef84f34020f259487cd1c9238b449cd2f75e670eb8e1e7984c092f54a0     6faea72b6dee0c3a21dd48ac5364be40e6fa4fe3d099b691b13e7e09b523dd53)

out_dir=${1:-./target/verity-vector}
mkdir -p "$out_dir"

data_img="$out_dir/data.img"
hash_img="$out_dir/hash.img"
root_hash_file="$out_dir/root_hash.txt"

python3 - "$data_img" <<'PYDATA'
from pathlib import Path
import sys

def block_bytes(prefix: bytes) -> bytes:
    data = bytearray(4096)
    data[:len(prefix)] = prefix
    return bytes(data)

path = Path(sys.argv[1])
path.write_bytes(b"".join([
    block_bytes(b"verity-block-000"),
    block_bytes(b"verity-block-001"),
    block_bytes(b"verity-block-002"),
]))
PYDATA

rm -f "$hash_img" "$root_hash_file"
veritysetup format     --no-superblock     --format=1     --hash=sha256     --data-block-size=4096     --hash-block-size=4096     --data-blocks=3     --salt=73616c74     --root-hash-file "$root_hash_file"     "$data_img"     "$hash_img"

actual_root_hash=$(tr -d '\n' < "$root_hash_file")
actual_hash_hex=$(od -An -tx1 -v "$hash_img" | tr -d ' \n')

if [ "$mode" = check ]; then
    if [ "$actual_root_hash" != "$expected_root_hash" ]; then
        echo "root hash mismatch" >&2
        echo "expected: $expected_root_hash" >&2
        echo "actual:   $actual_root_hash" >&2
        exit 1
    fi

    if ! python3 - "$hash_img" "$expected_hash_prefix_hex" <<'PYCHECK'
from pathlib import Path
import sys

hash_img = Path(sys.argv[1])
expected_prefix = bytes.fromhex(sys.argv[2])
actual = hash_img.read_bytes()
expected = expected_prefix + bytes(4096 - len(expected_prefix))
if actual != expected:
    print('hash image mismatch', file=sys.stderr)
    print(f'expected prefix bytes: {len(expected_prefix)}', file=sys.stderr)
    print(f'actual bytes:          {len(actual)}', file=sys.stderr)
    actual_prefix = actual[:len(expected_prefix)].hex()
    print(f'expected prefix: {expected_prefix.hex()}', file=sys.stderr)
    print(f'actual prefix:   {actual_prefix}', file=sys.stderr)
    trailing = actual[len(expected_prefix):]
    if trailing.rstrip(b'\x00'):
        print('actual trailing bytes are not zero-padded as expected', file=sys.stderr)
    sys.exit(1)
PYCHECK
    then
        exit 1
    fi

    echo "frozen dm-verity vector matches veritysetup output"
    exit 0
fi

echo "root hash:"
printf '%s\n' "$actual_root_hash"
echo

echo "hash image hex:"
printf '%s\n' "$actual_hash_hex"
echo

echo "sample dm_mod.create fragment:"
printf '%s\n' "dm_mod.create=\"vm_verity,,,ro,0 24 verity 1 <data_dev> <hash_dev> 4096 4096 3 0 sha256 $actual_root_hash 73616c74\""
echo

echo "sample mapper-only boot args:"
printf '%s\n' "dm_mod.create=\"vm_verity,,,ro,0 24 verity 1 <data_dev> <hash_dev> 4096 4096 3 0 sha256 $actual_root_hash 73616c74\""
echo

echo "sample opt-in Makefile helper invocation:"
printf '%s\n' "make run_kernel_with_verity AUTO_TEST=boot DM_VERITY_CREATE_ARGS='dm_mod.create=\"vm_verity,,,ro,0 24 verity 1 <data_dev> <hash_dev> 4096 4096 3 0 sha256 $actual_root_hash 73616c74\"'"
echo

echo "sample maintained-vector helper invocation:"
printf '%s\n' "make run_kernel_with_verity_sample AUTO_TEST=boot"
echo

echo "direct-root boot args template for a bootable verified rootfs image:"
printf '%s\n' "root=/dev/dm-0 rootfstype=ext2 ro dm_mod.create=\"vm_verity,,,ro,0 24 verity 1 <data_dev> <hash_dev> 4096 4096 3 0 sha256 $actual_root_hash 73616c74\""
echo "note: this maintained tiny vector is mapper-only; use tools/generate_verity_root_boot_sample.sh and make check_verity_root_boot for the bootable ext2 root sample."
