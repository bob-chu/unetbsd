#!/bin/bash

set -e

# Build the project
meson setup build
cd build
ninja
cd ..

# Create a temporary directory for packaging
rm -rf package
mkdir -p package/bin
mkdir -p package/web

# Copy the necessary binaries
cp build/perf_tool package/bin/
cp build/ptm package/bin/
cp build/ptcp package/bin/

if [ -f "build/lb" ]; then
    cp build/lb package/bin/
fi

# Copy the ptweb/dist directory
cp -r ptweb/dist/* package/web/

# Copy the install.sh script
#cp install.sh package/

# Create a tarball
tar -czvf unetbsd.tar.gz -C package .

# Clean up
rm -rf package

echo "unetbsd.tar.gz created."
