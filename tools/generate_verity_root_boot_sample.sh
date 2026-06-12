#!/bin/sh
set -eu

usage() {
    cat <<'USAGE'
Usage: ./tools/generate_verity_root_boot_sample.sh [src_initramfs_dir] [out_dir]

Builds a bootable ext2 rootfs image from the maintained initramfs tree, then
formats a matching dm-verity hash image beside it.

Defaults:
  src_initramfs_dir = ./test/initramfs/build/initramfs
  out_dir           = ./target/verity-root-sample
USAGE
}

case "${1:-}" in
    --help|-h)
        usage
        exit 0
        ;;
esac

if [ "$#" -gt 2 ]; then
    usage >&2
    exit 2
fi

if ! command -v veritysetup >/dev/null 2>&1; then
    echo "veritysetup is required to generate a dm-verity root sample" >&2
    exit 1
fi

if ! command -v mkfs.ext2 >/dev/null 2>&1; then
    echo "mkfs.ext2 is required to generate a bootable ext2 root sample" >&2
    exit 1
fi

src_dir=${1:-./test/initramfs/build/initramfs}
out_dir=${2:-./target/verity-root-sample}

if [ ! -d "$src_dir" ]; then
    echo "source initramfs directory '$src_dir' does not exist" >&2
    exit 1
fi

mkdir -p "$out_dir"
root_img="$out_dir/rootfs.img"
hash_img="$out_dir/hash.img"
root_hash_file="$out_dir/root_hash.txt"
meta_file="$out_dir/geometry.env"
marker_rel="etc/verified-root-marker"
marker_text="dm-verity-root-sample"
image_size_mb=64
salt_hex=73616c74

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
stage_dir="$tmpdir/rootfs"
mkdir -p "$stage_dir"
cp -aL "$src_dir"/. "$stage_dir"/
printf '%s\n' "$marker_text" > "$stage_dir/$marker_rel"

truncate -s "${image_size_mb}M" "$root_img"
mkfs.ext2 -q -F -b 4096 -d "$stage_dir" "$root_img"

rm -f "$hash_img" "$root_hash_file"
num_data_blocks=$(( $(stat -c %s "$root_img") / 4096 ))
veritysetup format \
    --no-superblock \
    --format=1 \
    --hash=sha256 \
    --data-block-size=4096 \
    --hash-block-size=4096 \
    --data-blocks="$num_data_blocks" \
    --salt="$salt_hex" \
    --root-hash-file "$root_hash_file" \
    "$root_img" \
    "$hash_img" >/dev/null

root_hash=$(tr -d '\n' < "$root_hash_file")
num_sectors=$(( num_data_blocks * 8 ))
cat > "$meta_file" <<META
ROOT_HASH=$root_hash
NUM_DATA_BLOCKS=$num_data_blocks
NUM_SECTORS=$num_sectors
SALT_HEX=$salt_hex
MARKER_PATH=/$marker_rel
MARKER_TEXT=$marker_text
META

echo "bootable dm-verity root sample ready"
echo "root image:      $root_img"
echo "hash image:      $hash_img"
echo "root hash:       $root_hash"
echo "data blocks:     $num_data_blocks"
echo "logical sectors: $num_sectors"
echo "marker path:     /$marker_rel"
