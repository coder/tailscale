# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

FROM gcr.io/oss-fuzz-base/base-builder-go
COPY . $SRC/tailscale
WORKDIR $SRC/tailscale
COPY .clusterfuzzlite/build.sh $SRC/
