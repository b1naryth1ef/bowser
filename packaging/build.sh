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

# Build bowse
go build ../../cmd/bowser/bowser.go
go build ../../cmd/bowser-create-account/bowser-create-account.go

# Copy files in place
mv bowser usr/bin/
mv bowser-create-account usr/bin/
cp -r bowser etc/

popd

fpm \
  -s dir \
  -t deb \
  -v $VERSION \
  -n bowser \
  -m "Discord, Inc." \
  --url "https://github.com/discord/bowser" \
  build/=/

rm -r build
