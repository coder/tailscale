#!/bin/bash -eu
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

tool=github.com/AdamKorcz/go-118-fuzz-build
ref=fc5dc53b9db8a38c394c53d6e439a1410cf8fc19
work=$(mktemp -d)
version=$(awk '/^go / { print $2 }' go.mod)
goroot=$(GOTOOLCHAIN="go$version" go env GOROOT)
# The v2 builder modifies testing internals and must match the Go toolchain.
cp -a "$goroot/." "$work/goroot"
chmod -R u+w "$work/goroot"
export GOROOT="$work/goroot" GOTOOLCHAIN=local
export PATH="$work/bin:$GOROOT/bin:$PATH"
GOBIN="$work/bin" go install "$tool@$ref"
mv "$work/bin/go-118-fuzz-build" "$work/bin/go-118-fuzz-build_v2"
go get "$tool/testing@$ref"
compile_native_go_fuzzer_v2 tailscale.com/net/dns/resolver FuzzClampEDNSSize clamp_edns_size
compile_native_go_fuzzer_v2 tailscale.com/util/hashx Fuzz hashx
compile_native_go_fuzzer_v2 tailscale.com/util/deephash FuzzTime deephash_time
compile_native_go_fuzzer_v2 tailscale.com/util/deephash FuzzAddr deephash_addr
