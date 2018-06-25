OS := $(shell uname)
TARGET := ipd2

ifeq ($(OS),Linux)
	TAR_OPTS := --wildcards
endif

guard-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 0; \
	fi

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

build: build_darwin_amd64 \
	build_linux_amd64 \
	build_windows_amd64

build_darwin_%: GOOS := darwin
build_linux_%: GOOS := linux
build_windows_%: GOOS := windows
build_windows_%: EXT := .exe

build_%_amd64: GOARCH := amd64

build_%:
	env GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -a -installsuffix cgo -o build/$(TARGET)-${TRAVIS_TAG}-$(GOOS)_$(GOARCH)$(EXT) ./cmd/ipd/main.go

clean:
	@echo "Cleaning up generated folders/files."
	rm -fr build