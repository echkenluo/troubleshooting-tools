#!/bin/bash
#
# Docker internal build script for measurement-tools RPM
# This script runs inside the Docker container
#
# Usage (inside container):
#   ./build-docker.sh [VERSION] [DIST] [RELEASE]

set -e

VERSION="${1:-1.0.0}"
DIST="${2:-el7}"
RELEASE="${3:-1}"
PKG_NAME="measurement-tools"

echo "Building ${PKG_NAME}-${VERSION}-${RELEASE}.${DIST}.noarch.rpm"

# Fix CentOS 7 EOL repo issue
if [ -f /etc/centos-release ] && grep -q "CentOS Linux release 7" /etc/centos-release 2>/dev/null; then
    echo "Configuring CentOS 7 vault repository..."
    sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true
    sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo 2>/dev/null || true
fi

# Install rpm-build
echo "Installing rpm-build..."
yum install -y rpm-build tar gzip 2>/dev/null || dnf install -y rpm-build tar gzip 2>/dev/null || true

# Create rpmbuild directories
mkdir -p ~/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball from mounted /src
SOURCE_DIR=~/rpmbuild/SOURCES/${PKG_NAME}-${VERSION}
mkdir -p "${SOURCE_DIR}"
cp -rp /src/measurement-tools/* "${SOURCE_DIR}/"

# Remove unnecessary files
find "${SOURCE_DIR}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${SOURCE_DIR}" -type f -name "*.pyc" -delete 2>/dev/null || true
find "${SOURCE_DIR}" -type f -name ".DS_Store" -delete 2>/dev/null || true

# Create tarball
cd ~/rpmbuild/SOURCES
tar czf "${PKG_NAME}-${VERSION}.tar.gz" "${PKG_NAME}-${VERSION}"
rm -rf "${SOURCE_DIR}"

# Copy spec file
cp /build/measurement-tools.spec ~/rpmbuild/SPECS/

# Build RPM
echo "Building RPM..."
rpmbuild \
    --define "dist .${DIST}" \
    --define "version ${VERSION}" \
    --define "release_ver ${RELEASE}" \
    -ba ~/rpmbuild/SPECS/measurement-tools.spec

# Copy output to /output
echo "Copying RPMs to /output..."
cp ~/rpmbuild/RPMS/noarch/*.rpm /output/ 2>/dev/null || true
cp ~/rpmbuild/SRPMS/*.rpm /output/ 2>/dev/null || true

echo "Build complete!"
ls -la /output/*.rpm 2>/dev/null || echo "No RPMs found"
