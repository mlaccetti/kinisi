OS := $(shell uname)
TARGET := kinisi

ifeq ($(OS),Windows_NT)
	BUILD_TAG := $(shell if %TRAVIS_TAG% == %^TRAVIS_TAG% (echo "No tag") else echo ("tag"))
	PWD := $(shell echo %CWD%)
else
	BUILD_TAG := $(shell [ -z "${TRAVIS_TAG}" ] && date +%s || echo "${TRAVIS_TAG}")
	PWD := $(shell pwd)

	ifeq ($(OS),Linux)
		TAR_OPTS := --wildcards
	endif
endif

all: deps test vet build

fmt:
	@echo "Formatting all the things..."
	go fmt ./...
	@echo ""

vet:
	@echo "Vetting stuff"
	go vet ./...
	@echo ""

deps:
	@echo "Ensuring dependencies are in place"
	dep ensure
	@echo ""

test:
	@echo "Running tests"
	go test ./...
	@echo ""

build: build_linux_amd64
#build: build_darwin_amd64 \
#	build_linux_amd64 \
#	build_windows_amd64

build_darwin_%: GOOS := darwin
build_linux_%: GOOS := linux
build_windows_%: GOOS := windows
build_windows_%: EXT := .exe

build_%_amd64: GOARCH := amd64

build_%:
	@echo "Running on $(OS)"
	env GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=1 go build -v -x -a -installsuffix cgo -o build/$(TARGET)-$(BUILD_TAG)-$(GOOS)_$(GOARCH)$(EXT) cmd/main.go

clean:
	@echo "Cleaning up generated folders/files."
	rm -fr build

docker-build:
	docker build -t mlaccetti/kinisi:build .

docker-run: docker-build
	docker run -v $(PWD)/../../../..:/go -it mlaccetti/kinisi:build