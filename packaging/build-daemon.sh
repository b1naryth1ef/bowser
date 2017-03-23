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

# Build bowser
go build ../../cmd/bowser/bowser.go

# Copy files in place
mv bowser usr/bin/
cp -r ../bowser etc/

popd

fpm \
  -s dir \
  -t deb \
  -v $VERSION \
  -n bowser \
  -m "Andrei Zbikowski <b1naryth1ef@gmail.com>" \
  --url "https://github.com/b1naryth1ef/bowser" \
  --deb-upstart upstart/bowser.conf \
  build/=/

rm -r build
