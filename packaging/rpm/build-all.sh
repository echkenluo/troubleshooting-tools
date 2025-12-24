#!/bin/bash
#
# Build measurement-tools RPM for all distributions
#
# Usage:
#   ./build-all.sh [OPTIONS] [VERSION] [RELEASE]
#
# Options:
#   -D, --docker    Use Docker to build (required on macOS)
#
# Examples:
#   ./build-all.sh 1.0.0           # Native build on Linux
#   ./build-all.sh 1.0.0 2         # Build with release version 2
#   ./build-all.sh -D 1.0.0        # Docker build (macOS/Linux)
#   ./build-all.sh -D 1.0.0 3      # Docker build with release 3
#   ./build-all.sh --docker        # Docker build with default version

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USE_DOCKER=""
VERSION="1.0.0"
RELEASE="1"
VERSION_SET=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -D|--docker)
            USE_DOCKER="-D"
            shift
            ;;
        *)
            # First positional arg is VERSION, second is RELEASE
            if [ "$VERSION_SET" = false ]; then
                VERSION="$1"
                VERSION_SET=true
            else
                RELEASE="$1"
            fi
            shift
            ;;
    esac
done

OUTPUT_DIR="${SCRIPT_DIR}/output"

echo "Building measurement-tools RPM v${VERSION}-${RELEASE} for all distributions..."
[ -n "$USE_DOCKER" ] && echo "Using Docker for builds..."
echo ""

# Build for each distribution
for dist in el7 oe1 tl3; do
    echo "=========================================="
    echo "Building for dist: ${dist}"
    echo "=========================================="
    "${SCRIPT_DIR}/build.sh" -v "${VERSION}" -r "${RELEASE}" -d "${dist}" ${USE_DOCKER} -o "${OUTPUT_DIR}"
    echo ""
done

echo "=========================================="
echo "Build Summary"
echo "=========================================="
echo "Output directory: ${OUTPUT_DIR}"
echo ""
echo "Generated RPMs:"
ls -la "${OUTPUT_DIR}"/*.noarch.rpm 2>/dev/null || echo "No RPMs found"
echo ""
echo "Upload instructions:"
echo "  el7 x86_64:     scp ${OUTPUT_DIR}/*el7*.rpm user@192.168.17.20:/repo/pub/smartxos/el7/2-qa/"
echo "  oe2003 x86_64:  scp ${OUTPUT_DIR}/*oe1*.rpm user@192.168.17.20:/repo/pub/openeuler/oe2003/qa/x86_64/"
echo "  oe2003 aarch64: scp ${OUTPUT_DIR}/*oe1*.rpm user@192.168.17.20:/repo/pub/openeuler/oe2003/qa/aarch64/"
echo "  tl3 x86_64:     scp ${OUTPUT_DIR}/*tl3*.rpm user@192.168.17.20:/repo/pub/tencentos/tl3/qa/x86_64/"
echo "  tl3 aarch64:    scp ${OUTPUT_DIR}/*tl3*.rpm user@192.168.17.20:/repo/pub/tencentos/tl3/qa/aarch64/"
echo ""
echo "After upload, run 'createrepo --update <repo_path>' on the repo server."
