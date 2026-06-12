# SPDX-License-Identifier: MPL-2.0

# =========================== Makefile options. ===============================

# Global build options.
TARGET_ARCH ?= x86_64
BENCHMARK ?= none
BOOT_METHOD ?= grub-rescue-iso
BOOT_PROTOCOL ?= multiboot2
ENABLE_KVM ?= 1
INTEL_TDX ?= 0
MEM ?= 8G
OVMF ?= on
RELEASE ?= 0
RELEASE_LTO ?= 0
LOG_LEVEL ?= error
SCHEME ?= ""
SMP ?= 1
OSTD_TASK_STACK_SIZE_IN_PAGES ?= 64
FEATURES ?=
NO_DEFAULT_FEATURES ?= 0
COVERAGE ?= 0

# Specify the primary system console (supported: tty0, ttyS0, hvc0).
# - tty0: The active virtual terminal (VT).
# - ttyS0: The serial (UART) terminal.
# - hvc0: The virtio-console terminal.
# Asterinas will automatically fall back to tty0 if hvc0 is not available.
# Note that currently the virtual terminal (tty0) can only work with
# linux-efi-handover64 and linux-efi-pe64 boot protocol.
CONSOLE ?= hvc0
# End of global build options.

# GDB debugging and profiling options.
GDB_TCP_PORT ?= 1234
GDB_PROFILE_FORMAT ?= flame-graph
GDB_PROFILE_COUNT ?= 200
GDB_PROFILE_INTERVAL ?= 0.1
# End of GDB options.

# The Makefile provides a way to run arbitrary tests in the kernel
# mode using the kernel command line.
# Here are the options for the auto test feature.
AUTO_TEST ?= none
# Optional extra kernel command-line arguments appended to cargo-osdk invocations.
EXTRA_KCMD_ARGS ?=
# Optional raw QEMU arguments appended to cargo-osdk invocations.
EXTRA_QEMU_ARGS ?=
# Optional dm_mod.create fragment appended by the opt-in dm-verity helper target.
DM_VERITY_CREATE_ARGS ?=
DM_VERITY_SAMPLE_DIR ?= $(abspath target/verity-vector)
DM_VERITY_SAMPLE_DATA_IMG ?= $(DM_VERITY_SAMPLE_DIR)/data.img
DM_VERITY_SAMPLE_HASH_IMG ?= $(DM_VERITY_SAMPLE_DIR)/hash.img
DM_VERITY_SAMPLE_ROOT_HASH_FILE ?= $(DM_VERITY_SAMPLE_DIR)/root_hash.txt
DM_VERITY_SAMPLE_DATA_DEV ?= /dev/vdc
DM_VERITY_SAMPLE_HASH_DEV ?= /dev/vdd
DM_VERITY_ROOT_SAMPLE_DIR ?= $(abspath target/verity-root-sample)
DM_VERITY_ROOT_SAMPLE_DATA_IMG ?= $(DM_VERITY_ROOT_SAMPLE_DIR)/rootfs.img
DM_VERITY_ROOT_SAMPLE_HASH_IMG ?= $(DM_VERITY_ROOT_SAMPLE_DIR)/hash.img
DM_VERITY_ROOT_SAMPLE_ROOT_HASH_FILE ?= $(DM_VERITY_ROOT_SAMPLE_DIR)/root_hash.txt
DM_VERITY_ROOT_SAMPLE_GEOMETRY_FILE ?= $(DM_VERITY_ROOT_SAMPLE_DIR)/geometry.env
DM_VERITY_ROOT_SAMPLE_DATA_DEV ?= /dev/vdc
DM_VERITY_ROOT_SAMPLE_HASH_DEV ?= /dev/vdd
# Specify whether to build conformance tests under `test/initramfs/src/conformance`.
ENABLE_CONFORMANCE_TEST ?= false
CONFORMANCE_TEST_SUITE ?= ltp
CONFORMANCE_TEST_WORKDIR ?= /tmp
# Whitespace-separated extra blocklist paths for conformance runners.
# - `gvisor` treats each entry as a directory relative to its runner directory,
#   and loads a per-test blocklist file from that directory.
# - `kselftest` treats each entry as a blocklist file relative to its runner
#   directory, and appends that file directly.
EXTRA_BLOCKLISTS ?= ""
# Parameters for xfstests.
XFSTESTS_RUNLIST ?= /opt/xfstests/short.list
XFSTESTS_DISK_SIZE ?= 12G
XFSTESTS_TEST_DEV ?= /dev/vdc
XFSTESTS_SCRATCH_DEV ?= /dev/vdd
# Specify whether to build regression tests under `test/initramfs/src/regression`.
ENABLE_REGRESSION_TEST ?= false
# End of auto test features.

# Network settings
# NETDEV possible values are user,tap
NETDEV ?= user
VHOST ?= off
# The name server listed by /etc/resolv.conf inside the Asterinas VM
DNS_SERVER ?= none
# End of network settings

# NixOS settings
NIXOS_DISK_SIZE_IN_MB ?= 8192
NIXOS_DISABLE_SYSTEMD ?= false
# The following option is only effective when NIXOS_DISABLE_SYSTEMD is set to 'true'.
# Use a login shell to ensure that environment variables are initialized correctly.
NIXOS_STAGE_2_INIT ?= /bin/sh -l
# End of NixOS settings

# ISO installer settings
AUTO_INSTALL ?= true
# End of ISO installer settings

# Cachix binary cache settings
CACHIX_AUTH_TOKEN ?=
RELEASE_CACHIX_NAME ?= "aster-nixos-release"
RELEASE_SUBSTITUTER ?= https://aster-nixos-release.cachix.org
RELEASE_TRUSTED_PUBLIC_KEY ?= aster-nixos-release.cachix.org-1:xB6U/f5ck5vGDJZ04kPp3zGpZ4Nro9X4+TSSMAETVFE=
DEV_CACHIX_NAME ?= "aster-nixos-dev"
DEV_SUBSTITUTER ?= https://aster-nixos-dev.cachix.org
DEV_TRUSTED_PUBLIC_KEY ?= aster-nixos-dev.cachix.org-1:xrCbE2flfliFTQCY/2HeJoT2tCO+5kMTZeLIUH9lnIA=
# End of Cachix binary cache settings

# ========================= End of Makefile options. ==========================

export OSDK_TARGET_ARCH=$(TARGET_ARCH)

SHELL := /bin/bash

CARGO_OSDK := ~/.cargo/bin/cargo-osdk

# Common arguments for `cargo osdk` `build`, `run` and `test` commands.
CARGO_OSDK_COMMON_ARGS :=
# The build arguments also apply to the `cargo osdk run` command.
CARGO_OSDK_BUILD_ARGS := --kcmd-args="ostd.log_level=$(LOG_LEVEL)"
CARGO_OSDK_BUILD_ARGS += --kcmd-args="console=$(CONSOLE)"
ifneq ($(strip $(EXTRA_KCMD_ARGS)),)
CARGO_OSDK_BUILD_ARGS += --kcmd-args='$(EXTRA_KCMD_ARGS)'
endif
CARGO_OSDK_TEST_ARGS :=

ifeq ($(AUTO_TEST), conformance)
ENABLE_CONFORMANCE_TEST := true
CARGO_OSDK_BUILD_ARGS += --kcmd-args="CONFORMANCE_TEST_SUITE=$(CONFORMANCE_TEST_SUITE)"
CARGO_OSDK_BUILD_ARGS += --kcmd-args="CONFORMANCE_TEST_WORKDIR=$(CONFORMANCE_TEST_WORKDIR)"
CARGO_OSDK_BUILD_ARGS += --kcmd-args="EXTRA_BLOCKLISTS=$(EXTRA_BLOCKLISTS)"
ifeq ($(CONFORMANCE_TEST_SUITE), xfstests)
CARGO_OSDK_BUILD_ARGS += --kcmd-args="XFSTESTS_RUNLIST=$(XFSTESTS_RUNLIST)"
CARGO_OSDK_BUILD_ARGS += --kcmd-args="XFSTESTS_TEST_DEV=$(XFSTESTS_TEST_DEV)"
CARGO_OSDK_BUILD_ARGS += --kcmd-args="XFSTESTS_SCRATCH_DEV=$(XFSTESTS_SCRATCH_DEV)"
endif
CARGO_OSDK_BUILD_ARGS += --init-args="/opt/run_conformance_test.sh"
else ifeq ($(AUTO_TEST), regression)
ENABLE_REGRESSION_TEST := true
CARGO_OSDK_BUILD_ARGS += --kcmd-args="INTEL_TDX=$(INTEL_TDX)"
CARGO_OSDK_BUILD_ARGS += --init-args="/test/run_regression_test.sh"
else ifeq ($(AUTO_TEST), boot)
CARGO_OSDK_BUILD_ARGS += --init-args="/test/boot_hello.sh"
else ifeq ($(AUTO_TEST), dm_verity_boot)
CARGO_OSDK_BUILD_ARGS += --init-args="/test/boot_dm_verity.sh"
else ifeq ($(AUTO_TEST), vsock)
ENABLE_REGRESSION_TEST := true
export VSOCK=on
CARGO_OSDK_BUILD_ARGS += --init-args="/test/run_vsock_test.sh"
endif

ifeq ($(RELEASE_LTO), 1)
CARGO_OSDK_COMMON_ARGS += --profile release-lto
OSTD_TASK_STACK_SIZE_IN_PAGES = 8
else ifeq ($(RELEASE), 1)
CARGO_OSDK_COMMON_ARGS += --release
	ifeq ($(TARGET_ARCH), riscv64)
	# FIXME: Unwinding in RISC-V seems to cost more stack space, so we increase
	# the stack size for it. This may need further investigation.
	# See https://github.com/asterinas/asterinas/pull/2383#discussion_r2307673156
	OSTD_TASK_STACK_SIZE_IN_PAGES = 16
	else
	OSTD_TASK_STACK_SIZE_IN_PAGES = 8
	endif
endif

# If the BENCHMARK is set, we will run the benchmark in the kernel mode.
ifneq ($(BENCHMARK), none)
CARGO_OSDK_BUILD_ARGS += --init-args="/benchmark/common/bench_runner.sh $(BENCHMARK) asterinas"
endif

ifeq ($(INTEL_TDX), 1)
BOOT_PROTOCOL = linux-efi-handover64
CARGO_OSDK_COMMON_ARGS += --scheme tdx
endif

ifeq ($(BOOT_PROTOCOL), multiboot)
BOOT_METHOD = qemu-direct
endif

ifeq ($(SCHEME), microvm)
BOOT_METHOD = qemu-direct
endif

ifeq ($(SCHEME), "")
	ifeq ($(TARGET_ARCH), riscv64)
	SCHEME = riscv
	else ifeq ($(TARGET_ARCH), loongarch64)
	SCHEME = loongarch
	endif
endif

ifneq ($(SCHEME), "")
CARGO_OSDK_COMMON_ARGS += --scheme $(SCHEME)
else
CARGO_OSDK_COMMON_ARGS += --boot-method="$(BOOT_METHOD)"
endif

ifeq ($(COVERAGE), 1)
CARGO_OSDK_COMMON_ARGS += --coverage
endif

ifdef FEATURES
CARGO_OSDK_COMMON_ARGS += --features="$(FEATURES)"
endif
ifeq ($(NO_DEFAULT_FEATURES), 1)
CARGO_OSDK_COMMON_ARGS += --no-default-features
endif

# To test the linux-efi-handover64 boot protocol, we need to use Debian's
# GRUB release, which is installed in /usr/bin in our Docker image.
ifeq ($(BOOT_PROTOCOL), linux-efi-handover64)
CARGO_OSDK_COMMON_ARGS += --grub-mkrescue=/usr/bin/grub-mkrescue --grub-boot-protocol="linux"
else ifeq ($(BOOT_PROTOCOL), linux-efi-pe64)
CARGO_OSDK_COMMON_ARGS += --grub-boot-protocol="linux"
else ifeq ($(BOOT_PROTOCOL), linux-legacy32)
CARGO_OSDK_COMMON_ARGS += --linux-x86-legacy-boot --grub-boot-protocol="linux" --strip-elf
else
CARGO_OSDK_COMMON_ARGS += --grub-boot-protocol=$(BOOT_PROTOCOL)
endif

ifeq ($(ENABLE_KVM), 1)
	ifeq ($(TARGET_ARCH), x86_64)
	CARGO_OSDK_COMMON_ARGS += --qemu-args="-accel kvm"
	endif
endif

ifneq ($(strip $(EXTRA_QEMU_ARGS)),)
CARGO_OSDK_COMMON_ARGS += --qemu-args="$(EXTRA_QEMU_ARGS)"
endif

# Skip GZIP to make encoding and decoding of initramfs faster
ifeq ($(INITRAMFS_SKIP_GZIP),1)
CARGO_OSDK_INITRAMFS_OPTION := --initramfs=$(abspath test/initramfs/build/initramfs.cpio)
CARGO_OSDK_COMMON_ARGS += $(CARGO_OSDK_INITRAMFS_OPTION)
endif

CARGO_OSDK_BUILD_ARGS += $(CARGO_OSDK_COMMON_ARGS)
CARGO_OSDK_TEST_ARGS += $(CARGO_OSDK_COMMON_ARGS)

# Pass make variables to all subdirectory makes
export

# OSDK dependencies
OSDK_SRC_FILES := \
	$(shell find osdk/Cargo.toml osdk/Cargo.lock osdk/src -type f)

.PHONY: all
all: kernel

# Install or update OSDK from source
# To uninstall, do `cargo uninstall cargo-osdk`
.PHONY: install_osdk
install_osdk:
	@# The `OSDK_LOCAL_DEV` environment variable is used for local development
	@# without the need to publish the changes of OSDK's self-hosted
	@# dependencies to `crates.io`.
	@OSDK_LOCAL_DEV=1 cargo install cargo-osdk --path osdk

# This will install and update OSDK automatically
$(CARGO_OSDK): $(OSDK_SRC_FILES)
	@$(MAKE) --no-print-directory install_osdk

.PHONY: check_osdk
check_osdk:
	@./tools/clippy_check.sh osdk

.PHONY: test_osdk
test_osdk:
	@cd osdk && \
		OSDK_LOCAL_DEV=1 cargo build && \
		OSDK_LOCAL_DEV=1 cargo test

.PHONY: check_vdso
check_vdso:
	@# Checking `VDSO_LIBRARY_DIR` environment variable
	@if [ -z "$(VDSO_LIBRARY_DIR)" ]; then \
		echo "Error: the VDSO_LIBRARY_DIR environment variable must be given."; \
		echo "    This variable points to a directory that provides Linux's vDSO files,"; \
		echo "    which is required to build Asterinas. Search for VDSO_LIBRARY_DIR"; \
		echo "    in Asterinas's Dockerfile for more information."; \
		exit 1; \
	fi

.PHONY: initramfs
initramfs: check_vdso
	@$(MAKE) --no-print-directory -C test/initramfs

# Build the kernel with an initramfs
.PHONY: kernel
kernel: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk build $(CARGO_OSDK_BUILD_ARGS)

# Build the kernel with an initramfs and then run it
.PHONY: run_kernel
run_kernel: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk run $(CARGO_OSDK_BUILD_ARGS)

# Build and run the kernel with an opt-in dm_mod.create fragment appended to the
# kernel command line. This keeps default boot flows unchanged.
.PHONY: run_kernel_with_verity
run_kernel_with_verity:
	@if [ -z '$(strip $(DM_VERITY_CREATE_ARGS))' ]; then \
		echo "Error: DM_VERITY_CREATE_ARGS must be set to a dm_mod.create fragment."; \
		exit 1; \
	fi
	@$(MAKE) --no-print-directory run_kernel EXTRA_KCMD_ARGS='$(strip $(EXTRA_KCMD_ARGS) $(DM_VERITY_CREATE_ARGS))' EXTRA_QEMU_ARGS='$(EXTRA_QEMU_ARGS)' AUTO_TEST='$(AUTO_TEST)'

.PHONY: run_kernel_with_verity_sample
run_kernel_with_verity_sample: refresh_verity_test_vector
	@root_hash=$$(tr -d '\n' < '$(DM_VERITY_SAMPLE_ROOT_HASH_FILE)'); \
	$(MAKE) --no-print-directory run_kernel_with_verity \
		AUTO_TEST='$(AUTO_TEST)' \
		EXTRA_QEMU_ARGS="-drive if=none,format=raw,id=verity_data,file=$(DM_VERITY_SAMPLE_DATA_IMG) -device virtio-blk-pci,bus=pcie.0,addr=0xa,drive=verity_data,serial=verity-data,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off -drive if=none,format=raw,id=verity_hash,file=$(DM_VERITY_SAMPLE_HASH_IMG) -device virtio-blk-pci,bus=pcie.0,addr=0xb,drive=verity_hash,serial=verity-hash,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off" \
		DM_VERITY_CREATE_ARGS="dm_mod.create=\"vm_verity,,,ro,0 24 verity 1 $(DM_VERITY_SAMPLE_DATA_DEV) $(DM_VERITY_SAMPLE_HASH_DEV) 4096 4096 3 0 sha256 $$root_hash 73616c74\""

.PHONY: refresh_verity_root_boot_sample
refresh_verity_root_boot_sample: initramfs
	@chmod +x ./tools/generate_verity_root_boot_sample.sh
	@./tools/generate_verity_root_boot_sample.sh ./test/initramfs/build/initramfs '$(DM_VERITY_ROOT_SAMPLE_DIR)'

.PHONY: run_kernel_with_verity_root_sample
run_kernel_with_verity_root_sample: refresh_verity_root_boot_sample
	@. '$(DM_VERITY_ROOT_SAMPLE_GEOMETRY_FILE)'; \
	$(MAKE) --no-print-directory run_kernel_with_verity \
		AUTO_TEST='$(AUTO_TEST)' \
		BOOT_PROTOCOL=multiboot \
		EXTRA_KCMD_ARGS='$(strip $(EXTRA_KCMD_ARGS) root=/dev/dm-0 rootfstype=ext2 ro init=/init)' \
		EXTRA_QEMU_ARGS="-drive if=none,format=raw,id=verity_root_data,file=$(DM_VERITY_ROOT_SAMPLE_DATA_IMG) -device virtio-blk-pci,bus=pcie.0,addr=0xa,drive=verity_root_data,serial=verity-root-data,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off -drive if=none,format=raw,id=verity_root_hash,file=$(DM_VERITY_ROOT_SAMPLE_HASH_IMG) -device virtio-blk-pci,bus=pcie.0,addr=0xb,drive=verity_root_hash,serial=verity-root-hash,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,request-merging=off,backend_defaults=off,discard=off,write-zeroes=off,event_idx=off,indirect_desc=off,queue_reset=off" \
		DM_VERITY_CREATE_ARGS="dm_mod.create=\"vm_verity,,,ro,0 $$NUM_SECTORS verity 1 $(DM_VERITY_ROOT_SAMPLE_DATA_DEV) $(DM_VERITY_ROOT_SAMPLE_HASH_DEV) 4096 4096 $$NUM_DATA_BLOCKS 0 sha256 $$ROOT_HASH $$SALT_HEX\""
# Check the running status of auto tests from the QEMU log
ifeq ($(AUTO_TEST), conformance)
	@tail --lines 100 qemu.log | grep -q "^All conformance tests passed." \
		|| (echo "Conformance test failed" && exit 1)
else ifeq ($(AUTO_TEST), regression)
	@tail --lines 100 qemu.log | grep -q "^All regression tests passed." \
		|| (echo "Regression test failed" && exit 1)
else ifeq ($(AUTO_TEST), boot)
	@tail --lines 100 qemu.log | grep -q "^Successfully booted." \
		|| (echo "Boot test failed" && exit 1)
else ifeq ($(AUTO_TEST), vsock)
	@tail --lines 100 qemu.log | grep -q "^Vsock test passed." \
		|| (echo "Vsock test failed" && exit 1)
endif

# Build the Asterinas NixOS ISO installer image
iso: BOOT_PROTOCOL = linux-efi-handover64
iso:
	@make kernel
	@if [ -n "$(NIXOS_TEST_SUITE)" ]; then \
        $(MAKE) --no-print-directory -C test/nixos iso; \
    else \
        ./tools/nixos/build_iso.sh; \
    fi

# Build the Asterinas NixOS ISO installer image and then do installation
run_iso: OVMF = off
run_iso:
	@./tools/nixos/run.sh iso

# Create an Asterinas NixOS installation on host
nixos: BOOT_PROTOCOL = linux-efi-handover64
nixos:
	@make kernel
	@if [ -n "$(NIXOS_TEST_SUITE)" ]; then \
        $(MAKE) --no-print-directory -C test/nixos nixos; \
    else \
        ./tools/nixos/build_nixos.sh; \
    fi

# After creating a Asterinas NixOS installation (via either the `run_iso` or `nixos` target),
# run the NixOS
run_nixos: OVMF = off
run_nixos:
	@if [ -n "$(NIXOS_TEST_SUITE)" ]; then \
        $(MAKE) --no-print-directory -C test/nixos run_nixos; \
    else \
        ./tools/nixos/run.sh nixos; \
    fi

# Build the Asterinas NixOS patched packages
cachix:
	@nix-build distro/cachix \
		--option extra-substituters "${RELEASE_SUBSTITUTER} ${DEV_SUBSTITUTER}" \
		--option extra-trusted-public-keys "${RELEASE_TRUSTED_PUBLIC_KEY} ${DEV_TRUSTED_PUBLIC_KEY}" \
		--out-link cachix.list

# Push the Asterinas NixOS patched packages to Cachix
.PHONY: push_cachix
push_cachix: USE_RELEASE_CACHE ?= 0
push_cachix: cachix
ifeq ($(USE_RELEASE_CACHE), 1)
	@cachix push $(RELEASE_CACHIX_NAME) < cachix.list
else
	@cachix push $(DEV_CACHIX_NAME) < cachix.list
endif

.PHONY: gdb_server
gdb_server: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk run $(CARGO_OSDK_BUILD_ARGS) --gdb-server wait-client,vscode,addr=:$(GDB_TCP_PORT)

.PHONY: gdb_client
gdb_client: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk debug $(CARGO_OSDK_BUILD_ARGS) --remote :$(GDB_TCP_PORT)

.PHONY: profile_server
profile_server: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk run $(CARGO_OSDK_BUILD_ARGS) --gdb-server addr=:$(GDB_TCP_PORT)

.PHONY: profile_client
profile_client: initramfs $(CARGO_OSDK)
	@cd kernel && cargo osdk profile $(CARGO_OSDK_BUILD_ARGS) --remote :$(GDB_TCP_PORT) \
		--samples $(GDB_PROFILE_COUNT) --interval $(GDB_PROFILE_INTERVAL) --format $(GDB_PROFILE_FORMAT)

.PHONY: test
test: NON_DEFAULT_PACKAGE_NAMES = \
    $(shell ./tools/print_workspace_members.sh --non-default-ones --package-names)
test: TEST_PACKAGE_NAMES = \
    $(filter-out linux-bzimage-setup,$(NON_DEFAULT_PACKAGE_NAMES))
test:
	@if [ -n "$(TEST_PACKAGE_NAMES)" ]; then \
		cargo test $(addprefix -p ,$(TEST_PACKAGE_NAMES)); \
	fi

.PHONY: ktest
ktest: CONSOLE = ttyS0
ktest: initramfs $(CARGO_OSDK)
	@# cargo-osdk tests default workspace members.
	@# `linux-bzimage-setup` is left out of `default-members`
	@# because it is hard to unit test.
	@cargo osdk test $(CARGO_OSDK_TEST_ARGS)

.PHONY: docs
docs: private DEFAULT_PACKAGE_NAMES = \
    $(shell ./tools/print_workspace_members.sh --default-ones --package-names)
docs: private DEFAULT_NON_KERNEL_PACKAGE_NAMES = \
    $(filter-out aster-kernel,$(DEFAULT_PACKAGE_NAMES))
docs: private NON_DEFAULT_PACKAGE_NAMES = \
    $(shell ./tools/print_workspace_members.sh --non-default-ones --package-names)
docs: private DOC_NON_DEFAULT_PACKAGE_NAMES = \
    $(filter-out linux-bzimage-setup,$(NON_DEFAULT_PACKAGE_NAMES))
docs: $(CARGO_OSDK)
	@if [ -n "$(DEFAULT_NON_KERNEL_PACKAGE_NAMES)" ]; then \
		RUSTDOCFLAGS="-Dwarnings" cargo osdk doc $(addprefix -p ,$(DEFAULT_NON_KERNEL_PACKAGE_NAMES)) --no-deps; \
	fi
	@if [ -n "$(DOC_NON_DEFAULT_PACKAGE_NAMES)" ]; then \
		RUSTDOCFLAGS="-Dwarnings" cargo doc $(addprefix -p ,$(DOC_NON_DEFAULT_PACKAGE_NAMES)) --no-deps; \
	fi
	@# The kernel crate is primarily composed of private items.
	@# Include --document-private-items to fully check internal documentation.
	@RUSTDOCFLAGS="-Dwarnings --document-private-items -Arustdoc::private_intra_doc_links" \
		cargo osdk doc -p aster-kernel --no-deps
	@if [ "$(TARGET_ARCH)" = "x86_64" ]; then \
		cd ostd/libs/linux-bzimage/setup && RUSTDOCFLAGS="-Dwarnings" cargo osdk doc --no-deps; \
	fi

.PHONY: book
book: book/mermaid.min.js book/mermaid-init.js
	@cd book && mdbook build

book/mermaid.min.js book/mermaid-init.js:
	@mdbook-mermaid install book/

.PHONY: format
format:
	@./tools/format_all.sh
	@nixfmt ./distro
	@$(MAKE) --no-print-directory -C test/initramfs format
	@$(MAKE) --no-print-directory -C test/nixos format

.PHONY: refresh_verity_test_vector
refresh_verity_test_vector:
	@./tools/generate_verity_test_vector.sh

.PHONY: check_verity_test_vector
check_verity_test_vector:
	@./tools/generate_verity_test_vector.sh --check

.PHONY: check_verity_test_vector_boot
check_verity_test_vector_boot:
	@$(MAKE) --no-print-directory run_kernel_with_verity_sample AUTO_TEST=boot

.PHONY: check_verity_root_boot
check_verity_root_boot:
	@$(MAKE) --no-print-directory run_kernel_with_verity_root_sample AUTO_TEST=dm_verity_boot

.PHONY: test_dm_verity_boot
test_dm_verity_boot:
	@$(MAKE) --no-print-directory run_kernel_with_verity_sample AUTO_TEST=dm_verity_boot BOOT_PROTOCOL=multiboot

.PHONY: check
check: private WORKSPACE_MEMBER_DIRS = \
    $(shell ./tools/print_workspace_members.sh)
check: $(CARGO_OSDK)
	@# Check formatting issues of the Rust code
	@./tools/format_all.sh --check
	@
	@# Check if all workspace members enable workspace lints
	@for dir in $(WORKSPACE_MEMBER_DIRS); do \
		if [[ "$$(tail -2 $$dir/Cargo.toml)" != "[lints]"$$'\n'"workspace = true" ]]; then \
			echo "Error: Workspace lints in $$dir are not enabled"; \
			exit 1; \
		fi; \
	done
	@
	@# Check compilation of the Rust code
	@./tools/clippy_check.sh workspace
	@
	@# Check formatting issues of the C code and Nix files (regression tests)
	@$(MAKE) --no-print-directory -C test/initramfs check
	@
	@# Check formatting issues of the Rust code in NixOS tests
	@$(MAKE) --no-print-directory -C test/nixos check
	@
	@# Check typos
	@typos
	@# Check formatting issues of Nix files under distro directory
	@nixfmt --check ./distro

.PHONY: clean
clean:
	@echo "Cleaning up Asterinas workspace target files"
	@cargo clean
	@echo "Cleaning up OSDK workspace target files"
	@cd osdk && cargo clean
	@echo "Cleaning up mdBook output files"
	@cd book && mdbook clean
	@echo "Cleaning up test target files"
	@$(MAKE) --no-print-directory -C test/initramfs clean
	@echo "Uninstalling OSDK"
	@rm -f $(CARGO_OSDK)
