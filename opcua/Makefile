# edgeo-opcua Makefile
# Cross-platform build for Linux, macOS, and Windows

BINARY_NAME=edgeo-opcua
CMD_PATH=./cmd/edgeo-opcua
BIN_DIR=bin
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build clean linux darwin windows help

all: build

# Build for current platform
build:
	@mkdir -p $(BIN_DIR)
	go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)"

# Build for all platforms
build-all: linux darwin windows
	@echo "Build complete for all platforms"

# Linux builds
linux: linux-amd64 linux-arm64

linux-amd64:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)-linux-amd64"

linux-arm64:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)-linux-arm64"

# macOS builds
darwin: darwin-amd64 darwin-arm64

darwin-amd64:
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64"

darwin-arm64:
	@mkdir -p $(BIN_DIR)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64"

# Windows builds
windows: windows-amd64

windows-amd64:
	@mkdir -p $(BIN_DIR)
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe"

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR)
	@echo "Cleaned $(BIN_DIR)"

# Install to GOPATH/bin
install:
	go install $(LDFLAGS) $(CMD_PATH)
	@echo "Installed $(BINARY_NAME)"

help:
	@echo "edgeo-opcua Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build       Build for current platform"
	@echo "  make build-all   Build for all platforms (Linux, macOS, Windows)"
	@echo "  make linux       Build for Linux (amd64 and arm64)"
	@echo "  make darwin      Build for macOS (amd64 and arm64)"
	@echo "  make windows     Build for Windows (amd64)"
	@echo "  make clean       Remove build artifacts"
	@echo "  make install     Install to GOPATH/bin"
	@echo "  make help        Show this help"
	@echo ""
	@echo "Individual platform builds:"
	@echo "  make linux-amd64"
	@echo "  make linux-arm64"
	@echo "  make darwin-amd64"
	@echo "  make darwin-arm64"
	@echo "  make windows-amd64"
