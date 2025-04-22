#!/usr/bin/env bash
# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause
#
# gocross-wrapper.sh is a wrapper that can be aliased to 'go', which
# transparently builds gocross using a "bootstrap" Go toolchain, and
# then invokes gocross.

set -euo pipefail

if [[ "${CI:-}" == "true" ]]; then
  set -x
fi

# Locate a bootstrap toolchain and (re)build gocross if necessary. We run all of
# this in a subshell because posix shell semantics make it very easy to
# accidentally mutate the input environment that will get passed to gocross at
# the bottom of this script.
(
  repo_root="${BASH_SOURCE%/*}/../.."

  # Figuring out if gocross needs a rebuild, as well as the rebuild itself, need
  # to happen with CWD inside this repo. Since we're in a subshell entirely
  # dedicated to wrangling gocross and toolchains, cd over now before doing
  # anything further so that the rest of this logic works the same if gocross is
  # being invoked from somewhere else.
  cd "$repo_root"

  # Binaries run with `gocross run` can reinvoke gocross, resulting in a
  # potentially fancy build that invokes external linkers, might be
  # cross-building for other targets, and so forth. In one hilarious
  # case, cmd/cloner invokes go with GO111MODULE=off at some stage.
  #
  # Anyway, build gocross in a stripped down universe.
  gocross_path="gocross"
  gocross_ok=0
  wantver="$(git rev-parse HEAD)"
  if [[ -x "$gocross_path" ]]; then
    gotver="$($gocross_path gocross-version 2>/dev/null || echo '')"
    if [[ "$gotver" == "$wantver" ]]; then
      gocross_ok=1
    fi
  fi
  if [[ "$gocross_ok" == "0" ]]; then
    unset GOOS
    unset GOARCH
    unset GO111MODULE
    unset GOROOT
    export CGO_ENABLED=0
    go build -o "$gocross_path" -ldflags "-X tailscale.com/version.gitCommitStamp=$wantver" tailscale.com/tool/gocross
  fi
) # End of the subshell execution.

exec "${BASH_SOURCE%/*}/../../gocross" "$@"
