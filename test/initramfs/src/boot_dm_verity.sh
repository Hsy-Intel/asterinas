#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

if [ -f /etc/verified-root-marker ]; then
    marker=$(cat /etc/verified-root-marker)
    if [ "$marker" != "dm-verity-root-sample" ]; then
        echo "verified root marker mismatch" >&2
        echo "expected: dm-verity-root-sample" >&2
        echo "actual:   $marker" >&2
        exit 1
    fi

    echo "Successfully verified dm-verity boot path."
    exit 0
fi

expected_block0_prefix="verity-block-000"
expected_block1_prefix="verity-block-001"

if [ ! -b /dev/dm-0 ]; then
    echo "Expected /dev/dm-0 to be a block device" >&2
    echo "available block devices:" >&2
    ls -1 /dev/vd* /dev/dm* 2>/dev/null >&2 || true
    exit 1
fi

actual_block0_prefix=$(dd if=/dev/dm-0 bs=512 count=1 2>/dev/null | head -c 16)
if [ "$actual_block0_prefix" != "$expected_block0_prefix" ]; then
    echo "dm-verity block 0 prefix mismatch" >&2
    echo "expected: $expected_block0_prefix" >&2
    echo "actual:   $actual_block0_prefix" >&2
    exit 1
fi

actual_block1_prefix=$(dd if=/dev/dm-0 bs=512 skip=8 count=1 2>/dev/null | head -c 16)
if [ "$actual_block1_prefix" != "$expected_block1_prefix" ]; then
    echo "dm-verity block 1 prefix mismatch" >&2
    echo "expected: $expected_block1_prefix" >&2
    echo "actual:   $actual_block1_prefix" >&2
    exit 1
fi

echo "Successfully verified dm-verity boot path."
