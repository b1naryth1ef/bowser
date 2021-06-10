.PHONY: test build package

test:
	go test ./...

build:
	@mkdir -p build
	go build -o build/bowser ./cmd/bowser
	go build -o build/bowser-create-account ./cmd/bowser-create-account

package:
	pushd packaging; VERSION=$(shell git describe --tags) bash build.sh; popd
