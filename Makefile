OS_TARGETS := linux darwin windows
NAME := gen-self-signed-cert
RELEASE_VERSION := $(shell cat release_version.txt)
BIN_DIRS := $(foreach os,$(OS_TARGETS),out/$(os))

.PHONY: all
all: $(BIN_DIRS)

out/linux: main.go
	CGO_ENABLED=0 GOOS=linux go build -o out/linux/$(NAME)

out/darwin: main.go
	CGO_ENABLED=0 GOOS=darwin go build -o out/darwin/$(NAME)

out/windows: main.go
	CGO_ENABLED=0 GOOS=windows go build -o out/windows/$(NAME).exe

RELEASE_BASE := out/release/$(NAME)_v$(RELEASE_VERSION)
RELEASES := $(foreach os,$(OS_TARGETS),$(RELEASE_BASE)_$(os)_amd64.zip)
$(RELEASES): $(RELEASE_BASE)_%_amd64.zip : out/%
	mkdir -p out/release && zip -r $@ out/$*

.PHONY: release
release: $(RELEASES)
