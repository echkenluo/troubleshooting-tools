#!/bin/bash
#
# Build script for measurement-tools RPM
#
# Usage:
#   ./build.sh [OPTIONS]
#
# Options:
#   -v, --version VERSION   Package version (default: 1.0.0)
#   -r, --release RELEASE   Release version (default: 1)
#   -d, --dist DIST         Distribution tag: el7, oe1, tl3 (default: el7)
#   -o, --output DIR        Output directory for RPM (default: ./output)
#   -D, --docker            Use Docker to build (required on macOS)
#   -h, --help              Show this help message
#
# Examples:
#   ./build.sh -v 1.0.0 -d el7           # Build on Linux
#   ./build.sh -v 1.0.0 -r 2 -d el7      # Build with release 2
#   ./build.sh -v 1.0.0 -d el7 -D        # Build using Docker (macOS/Linux)
#   ./build.sh -v 1.0.0 -d oe1 -o /tmp/rpms
#   ./build.sh -d tl3
#
# Note: On macOS, the native rpmbuild has file magic issues with .bt files.
#       Use the -D/--docker option to build in a Linux container.

set -e

# Default values
VERSION="1.0.0"
RELEASE="1"
DIST="el7"
OUTPUT_DIR="./output"
USE_DOCKER=false

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SPEC_FILE="${SCRIPT_DIR}/measurement-tools.spec"

# Package name
PKG_NAME="measurement-tools"

usage() {
    head -25 "$0" | grep -E "^#" | sed 's/^# \?//'
    exit 0
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error() {
    echo "[ERROR] $*" >&2
    exit 1
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -r|--release)
            RELEASE="$2"
            shift 2
            ;;
        -d|--dist)
            DIST="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -D|--docker)
            USE_DOCKER=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            ;;
    esac
done

# Validate dist
case $DIST in
    el7|oe1|tl3)
        ;;
    *)
        error "Invalid dist: $DIST (must be el7, oe1, or tl3)"
        ;;
esac

log "Building ${PKG_NAME}-${VERSION}-${RELEASE}.${DIST}.noarch.rpm"

# Docker build mode
if [ "$USE_DOCKER" = true ]; then
    log "Using Docker to build..."

    # Select base image based on dist
    case $DIST in
        el7)
            DOCKER_IMAGE="centos:7"
            ;;
        oe1)
            DOCKER_IMAGE="openeuler/openeuler:20.03"
            ;;
        tl3)
            # TencentOS 3 is based on CentOS 8, use rockylinux as compatible base
            DOCKER_IMAGE="rockylinux:8"
            ;;
    esac

    mkdir -p "${OUTPUT_DIR}"
    OUTPUT_DIR_ABS="$(cd "${OUTPUT_DIR}" && pwd)"

    log "Docker image: ${DOCKER_IMAGE}"
    log "Output directory: ${OUTPUT_DIR_ABS}"

    docker run --rm \
        -v "${REPO_ROOT}:/src:ro" \
        -v "${SCRIPT_DIR}:/build:ro" \
        -v "${OUTPUT_DIR_ABS}:/output" \
        "${DOCKER_IMAGE}" \
        /bin/bash /build/build-docker.sh "${VERSION}" "${DIST}" "${RELEASE}"

    log "Build complete. Output files:"
    ls -la "${OUTPUT_DIR_ABS}"/*.rpm 2>/dev/null || true
    log "Done!"
    exit 0
fi

# Native build mode (Linux only)
# Create build directories
BUILD_ROOT=$(mktemp -d)
trap "rm -rf ${BUILD_ROOT}" EXIT

mkdir -p "${BUILD_ROOT}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "${OUTPUT_DIR}"

log "Build root: ${BUILD_ROOT}"

# Create source tarball
SOURCE_DIR="${BUILD_ROOT}/SOURCES/${PKG_NAME}-${VERSION}"
mkdir -p "${SOURCE_DIR}"

log "Creating source tarball..."
cp -rp "${REPO_ROOT}/measurement-tools"/* "${SOURCE_DIR}/"

# Remove unnecessary files
find "${SOURCE_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${SOURCE_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
find "${SOURCE_DIR}" -type f -name ".DS_Store" -delete 2>/dev/null || true

# Create tarball
cd "${BUILD_ROOT}/SOURCES"
tar czf "${PKG_NAME}-${VERSION}.tar.gz" "${PKG_NAME}-${VERSION}"
rm -rf "${SOURCE_DIR}"

log "Source tarball created: ${PKG_NAME}-${VERSION}.tar.gz"

# Copy spec file
cp "${SPEC_FILE}" "${BUILD_ROOT}/SPECS/"

# Build RPM
log "Building RPM with dist=${DIST}..."
rpmbuild \
    --define "_topdir ${BUILD_ROOT}" \
    --define "dist .${DIST}" \
    --define "version ${VERSION}" \
    --define "release_ver ${RELEASE}" \
    -ba "${BUILD_ROOT}/SPECS/measurement-tools.spec"

# Copy output RPMs
log "Copying RPMs to ${OUTPUT_DIR}..."
find "${BUILD_ROOT}/RPMS" -name "*.rpm" -exec cp {} "${OUTPUT_DIR}/" \;
find "${BUILD_ROOT}/SRPMS" -name "*.rpm" -exec cp {} "${OUTPUT_DIR}/" \;

# List output files
log "Build complete. Output files:"
ls -la "${OUTPUT_DIR}"/*.rpm 2>/dev/null || true

log "Done!"
