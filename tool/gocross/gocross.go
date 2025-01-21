// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// gocross is a wrapper around the `go` tool that invokes `go` from Tailscale's
// custom toolchain, with the right build parameters injected based on the
// native+target GOOS/GOARCH.
//
// In short, when aliased to `go`, using `go build`, `go test` behave like the
// upstream Go tools, but produce correctly configured, correctly linked
// binaries stamped with version information.

package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"tailscale.com/atomicfile"
	"tailscale.com/version"
)

func main() {
	if len(os.Args) > 1 {
		// These additional subcommands are various support commands to handle
		// integration with Tailscale's existing build system. Unless otherwise
		// specified, these are not stable APIs, and may change or go away at
		// any time.
		switch os.Args[1] {
		case "gocross-version":
			fmt.Println(version.GetMeta().GitCommit)
			os.Exit(0)
		case "is-gocross":
			// This subcommand exits with an error code when called on a
			// regular go binary, so it can be used to detect when `go` is
			// actually gocross.
			os.Exit(0)
		case "gocross-write-wrapper-script":
			if len(os.Args) != 3 {
				fmt.Fprintf(os.Stderr, "usage: gocross write-wrapper-script <path>\n")
				os.Exit(1)
			}
			if err := atomicfile.WriteFile(os.Args[2], wrapperScript, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "writing wrapper script: %v\n", err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}

	args := os.Args
	if os.Getenv("GOCROSS_BYPASS") == "" {
		newArgv, env, err := Autoflags(os.Args, runtime.GOROOT())
		if err != nil {
			fmt.Fprintf(os.Stderr, "computing flags: %v\n", err)
			os.Exit(1)
		}

		debug("Input: %s\n", formatArgv(os.Args))
		debug("Command: %s\n", formatArgv(newArgv))
		debug("Set the following flags/envvars:\n%s\n", env.Diff())

		args = newArgv
		if err := env.Apply(); err != nil {
			fmt.Fprintf(os.Stderr, "modifying environment: %v\n", err)
			os.Exit(1)
		}
	}

	cmd, err := exec.LookPath("go")
	if err == nil {
		cmd, err = filepath.Abs(cmd)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "looking up Go binary path: %v\n", err)
		os.Exit(1)
	}

	doExec(cmd, args, os.Environ())
}

//go:embed gocross-wrapper.sh
var wrapperScript []byte

func debug(format string, args ...any) {
	debug := os.Getenv("GOCROSS_DEBUG")
	var (
		out *os.File
		err error
	)
	switch debug {
	case "0", "":
		return
	case "1":
		out = os.Stderr
	default:
		out, err = os.OpenFile(debug, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0640)
		if err != nil {
			fmt.Fprintf(os.Stderr, "opening debug file %q: %v", debug, err)
			out = os.Stderr
		} else {
			defer out.Close() // May lose some write errors, but we don't care.
		}
	}

	fmt.Fprintf(out, format, args...)
}
