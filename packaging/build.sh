#!/bin/bash

if [ -z $VERSION ]; then
  echo "Please set the VERSION env variable"
  exit 1
fi

mkdir -p build
pushd build

# Create build folders for package
mkdir -p usr/bin
mkdir -p etc

# Build bowser for 64-bit Linux
GOOS=linux GOARCH=amd64 go build -o usr/bin/ ../../cmd/bowser
GOOS=linux GOARCH=amd64 go build -o usr/bin/ ../../cmd/bowser-create-account

# Include config files
cp -r ../bowser etc/

popd

fpm \
  -s dir \
  -t deb \
  -v $VERSION \
  -n bowser \
  -m "Discord, Inc." \
  --url "https://github.com/discord/bowser" \
  --deb-systemd systemd/bowser.service \
  build/=/

rm -r build
