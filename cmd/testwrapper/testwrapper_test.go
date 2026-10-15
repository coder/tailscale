// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/modfile"
)

const (
	okTest = "package ok\n\nimport \"testing\"\n\nfunc TestOK(t *testing.T) {}\n"

	flakyTest = `package flaky

import (
	"os"
	"testing"

	"tailscale.com/cmd/testwrapper/flakytest"
)

func TestOK(t *testing.T) {}

func TestFlaky(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/0")
	if os.Getenv(flakytest.FlakeAttemptEnv) == "1" {
		t.Fatal("failing first attempt")
	}
}
`

	flakyThenHangTest = `package flakyhang

import (
	"os"
	"testing"

	"tailscale.com/cmd/testwrapper/flakytest"
)

func TestFlaky(t *testing.T) {
	flakytest.Mark(t, "https://github.com/tailscale/tailscale/issues/0")
	if os.Getenv(flakytest.FlakeAttemptEnv) == "1" {
		t.Fatal("failing first attempt")
	}
}

func TestHang(t *testing.T) { <-make(chan struct{}) }
`

	compileErrorTest = "package broken\n\nimport \"testing\"\n\nfunc TestBroken(t *testing.T) { undefinedSymbol() }\n"
)

func TestCLI(t *testing.T) {
	t.Parallel()
	repo, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	repoMod, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	mf, err := modfile.ParseLax("go.mod", repoMod, nil)
	if err != nil || mf.Go == nil {
		t.Fatalf("reading repo go version: %v", err)
	}
	bin := filepath.Join(t.TempDir(), "testwrapper")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	buildCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(buildCtx, "go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("building testwrapper: %v\n%s", err, out)
	}

	tests := []struct {
		name     string
		files    map[string]string
		args     []string
		quiet    bool // run without -v, as CI does
		wantCode int
		want     []string
		// wantCount maps output substrings to their exact number of occurrences.
		wantCount map[string]int
	}{
		{name: "Pass", files: map[string]string{"ok/ok_test.go": okTest}, wantCode: 0, wantCount: map[string]int{"fixture/ok": 1}},
		{name: "InvalidGoFlags", files: map[string]string{"ok/ok_test.go": okTest}, args: []string{"-p=invalid"}, wantCode: 1, want: []string{"invalid value"}},
		{name: "CompileError", files: map[string]string{"broken/broken_test.go": compileErrorTest}, wantCode: 1, want: []string{"undefinedSymbol"}, wantCount: map[string]int{"FAIL\tfixture/broken": 1}},
		{
			name:      "MarkedFlakeThenPass",
			files:     map[string]string{"flaky/flaky_test.go": flakyTest},
			wantCode:  0,
			want:      []string{"[attempt=2]"},
			wantCount: map[string]int{"=== RUN   TestOK\n": 1, "=== RUN   TestFlaky\n": 2},
		},
		{
			name: "MixedFlakeAndCompileError",
			files: map[string]string{
				"flaky/flaky_test.go":   flakyTest,
				"broken/broken_test.go": compileErrorTest,
			},
			wantCode: 1,
			want:     []string{"undefinedSymbol"},
		},
		{
			name:     "NonFlakyFailure",
			files:    map[string]string{"fail/fail_test.go": "package fail\n\nimport \"testing\"\n\nfunc TestFail(t *testing.T) { t.Error(\"expected failure\") }\n"},
			wantCode: 1,
			want:     []string{"expected failure"},
		},
		{
			name:     "Timeout",
			files:    map[string]string{"hang/hang_test.go": "package hang\n\nimport \"testing\"\n\nfunc TestHang(t *testing.T) { <-make(chan struct{}) }\n"},
			args:     []string{"-timeout=1s"},
			wantCode: 1,
			want:     []string{"timed out"},
		},
		{
			name: "TimeoutAfterParallelPass",
			files: map[string]string{"hang/hang_test.go": `package hang

import (
	"testing"
	"time"
)

func TestHang(t *testing.T) { t.Parallel(); <-make(chan struct{}) }

func TestQuick(t *testing.T) { t.Parallel(); time.Sleep(100 * time.Millisecond) }
`},
			args:     []string{"-timeout=2s"},
			quiet:    true,
			wantCode: 1,
			want:     []string{"panic: test timed out", "running tests:"},
		},
		{
			name:     "FlakeThenTimeout",
			files:    map[string]string{"flakyhang/flakyhang_test.go": flakyThenHangTest},
			args:     []string{"-timeout=1s"},
			wantCode: 1,
			want:     []string{"timed out", "Not retrying flaky tests"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			gomod := fmt.Sprintf("module fixture\n\ngo %s\n\nrequire tailscale.com v0.0.0\n\nreplace tailscale.com => %q\n", mf.Go.Version, filepath.ToSlash(repo))
			if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
				t.Fatal(err)
			}
			for name, content := range tt.files {
				path := filepath.Join(dir, filepath.FromSlash(name))
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			args := []string{"./..."}
			if !tt.quiet {
				args = append([]string{"-v"}, args...)
			}
			cmd := exec.CommandContext(ctx, bin, append(args, tt.args...)...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=-mod=mod", "GOPROXY=off")
			outBytes, err := cmd.CombinedOutput()
			out := string(outBytes)
			if ctx.Err() != nil {
				t.Fatalf("testwrapper did not finish: %v\n%s", ctx.Err(), out)
			}
			code := 0
			if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("running testwrapper: %v", err)
			}
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d", code, tt.wantCode)
			}
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q", want)
				}
			}
			for sub, want := range tt.wantCount {
				if got := strings.Count(out, sub); got != want {
					t.Errorf("output has %q %d times, want %d", sub, got, want)
				}
			}
			if t.Failed() {
				t.Logf("output:\n%s", out)
			}
		})
	}
}
