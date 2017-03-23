#!/bin/bash

if [ -z $VERSION ]; then
  echo "Please set the VERSION env variable"
  exit 1
fi

mkdir -p build
pushd build

# Create build folders for package
mkdir -p usr/bin

# Build tools
go build ../../cmd/bowser-session-info/bowser-session-info.go
go build ../../cmd/bowser-create-account/bowser-create-account.go

# Copy files in place
mv bowser-session-info usr/bin/
mv bowser-create-account usr/bin/

popd

fpm \
  -s dir \
  -t deb \
  -v $VERSION \
  -n bowser-tools \
  -m "Andrei Zbikowski <b1naryth1ef@gmail.com>" \
  --url "https://github.com/b1naryth1ef/bowser" \
  build/=/

rm -r build
