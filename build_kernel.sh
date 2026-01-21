#!/bin/bash
set -e

# Set absolute paths
export KERNEL_DIR=$(pwd)
export CLANG_PATH=$(realpath ${KERNEL_DIR}/../toolchain/proton-clang)

# Clean build directory
rm -rf out
mkdir -p out

# Configuration
# Note: We use system host compiler for config tools
make O=out ARCH=arm64 nethunter_defconfig

# Build
echo "Starting build with Proton Clang..."
make -j$(nproc --all) \
    O=out \
    ARCH=arm64 \
    CC=${CLANG_PATH}/bin/clang \
    LD=${CLANG_PATH}/bin/ld.lld \
    AR=${CLANG_PATH}/bin/llvm-ar \
    NM=${CLANG_PATH}/bin/llvm-nm \
    OBJCOPY=${CLANG_PATH}/bin/llvm-objcopy \
    OBJDUMP=${CLANG_PATH}/bin/llvm-objdump \
    STRIP=${CLANG_PATH}/bin/llvm-strip \
    CROSS_COMPILE=${CLANG_PATH}/bin/aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=${CLANG_PATH}/bin/arm-linux-gnueabi- \
    HOSTCC=gcc \
    HOSTCXX=g++ \
    Image.gz-dtb

echo "Build complete. Output at out/arch/arm64/boot/Image.gz-dtb"