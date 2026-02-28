.PHONY: build build-small build-tiny clean test run

# Binary name
BINARY=mekongtunnel

# Build directory
BUILD_DIR=bin

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Version info (optional, for future use)
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME?=$(shell date -u '+%Y-%m-%d_%H:%M:%S')

# Linker flags for size optimization
# -s: Omit symbol table and debug info
# -w: Omit DWARF symbol table
LDFLAGS=-s -w -X main.version=$(VERSION)

# Build tags to exclude unnecessary features
BUILD_TAGS=

# Default target: optimized build
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY) ./cmd/mekongtunnel
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/mekong ./cmd/mekong

# Small build with all optimizations
build-small: clean
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY) ./cmd/mekongtunnel
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong ./cmd/mekong
	@echo "Binary size: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"
	@echo "Client size: $$(du -h $(BUILD_DIR)/mekong | cut -f1)"

# Build only the client CLI
build-client:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong ./cmd/mekong
	@echo "Client size: $$(du -h $(BUILD_DIR)/mekong | cut -f1)"

# Build client for all platforms (Mac, Linux, Windows)
build-client-all: clean
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong-darwin-amd64  ./cmd/mekong
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong-darwin-arm64  ./cmd/mekong
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong-linux-amd64   ./cmd/mekong
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong-linux-arm64   ./cmd/mekong
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/mekong-windows-amd64.exe ./cmd/mekong
	@echo "Client binaries:"
	@ls -lh $(BUILD_DIR)/mekong*

# Tiny build: smallest possible binary (requires upx)
build-tiny: build-small
	@command -v upx >/dev/null 2>&1 && upx --best --lzma $(BUILD_DIR)/$(BINARY) || echo "upx not installed, skipping compression"
	@echo "Final binary size: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"

# Build for multiple platforms
build-all: clean
	@mkdir -p $(BUILD_DIR)
	# Linux AMD64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-amd64 ./cmd/mekongtunnel
	# Linux ARM64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-linux-arm64 ./cmd/mekongtunnel
	# Darwin AMD64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 ./cmd/mekongtunnel
	# Darwin ARM64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) -ldflags="$(LDFLAGS)" -trimpath -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 ./cmd/mekongtunnel
	@echo "Built binaries:"
	@ls -lh $(BUILD_DIR)/

# Development build (faster, with debug info)
build-dev:
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY) ./cmd/mekongtunnel

# Run tests
test:
	$(GOTEST) -v ./...

# Run the application
run: build-dev
	$(BUILD_DIR)/$(BINARY)

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f $(BINARY)

# Tidy dependencies
tidy:
	$(GOMOD) tidy

# Show binary size comparison
size-check: build build-small
	@echo "\n=== Binary Size Comparison ==="
	@echo "Standard build: $$(du -h $(BUILD_DIR)/$(BINARY) | cut -f1)"

# Install to system
install: build-small
	sudo cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed to /usr/local/bin/$(BINARY)"
