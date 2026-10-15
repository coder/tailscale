// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// testwrapper is a wrapper for retrying flaky tests. It is an alternative to
// `go test` and re-runs failed marked flaky tests (using the flakytest pkg). It
// takes different arguments than go test and requires the first positional
// argument to be the pattern to test.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"golang.org/x/exp/maps"
	"tailscale.com/cmd/testwrapper/flakytest"
)

const maxAttempts = 3

type testAttempt struct {
	name          testName
	outcome       string // "pass", "fail", "skip"
	logs          bytes.Buffer
	isMarkedFlaky bool // set if the test is marked as flaky
	ended         bool // set after the test's "--- PASS" or "--- SKIP" line

	pkgFinished bool
}

type testName struct {
	pkg  string // "tailscale.com/types/key"
	name string // "TestFoo"
}

type packageTests struct {
	// pattern is the package pattern to run.
	// Must be a single pattern, not a list of patterns.
	pattern string // "./...", "./types/key"
	// tests is a list of tests to run. If empty, all tests in the package are
	// run.
	tests []string // ["TestFoo", "TestBar"]
}

type goTestOutput struct {
	Time    time.Time
	Action  string
	Package string
	Test    string
	Output  string
}

var debug = os.Getenv("TS_TESTWRAPPER_DEBUG") != ""

// runTests sends per-test and package outcomes to ch, then closes ch.
// It returns startup errors or the go test subprocess's exit error.
func runTests(ctx context.Context, attempt int, pt *packageTests, otherArgs []string, ch chan<- *testAttempt) error {
	defer close(ch)
	args := []string{"test", "-json", pt.pattern}
	args = append(args, otherArgs...)
	if len(pt.tests) > 0 {
		runArg := strings.Join(pt.tests, "|")
		args = append(args, "-run", runArg)
	}
	if debug {
		fmt.Println("running", strings.Join(args, " "))
	}
	cmd := exec.CommandContext(ctx, "go", args...)
	r, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}
	defer r.Close()
	cmd.Stderr = os.Stderr

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%d", flakytest.FlakeAttemptEnv, attempt))

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting test: %w", err)
	}

	jd := json.NewDecoder(r)
	resultMap := make(map[testName]*testAttempt)
	for {
		var goOutput goTestOutput
		if err := jd.Decode(&goOutput); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, os.ErrClosed) {
				break
			}

			// `go test -json` outputs invalid JSON when a build fails.
			// In that case, discard the the output and start reading again.
			// The build error will be printed to stderr.
			// See: https://github.com/golang/go/issues/35169
			if _, ok := err.(*json.SyntaxError); ok {
				jd = json.NewDecoder(r)
				continue
			}
			panic(err)
		}
		if goOutput.Test == "" {
			switch goOutput.Action {
			case "output":
				if !isPkgSummary(goOutput.Output, goOutput.Package) {
					fmt.Print(goOutput.Output)
				}
			case "build-output":
				fmt.Print(goOutput.Output)
			case "fail", "pass", "skip":
				if goOutput.Action == "fail" {
					// Timeouts omit the final per-test event; report those tests as failed.
					for name, test := range resultMap {
						if name.pkg == goOutput.Package && test.outcome == "" {
							test.outcome = "fail"
							ch <- test
						}
					}
				}
				ch <- &testAttempt{
					name: testName{
						pkg: goOutput.Package,
					},
					outcome:     goOutput.Action,
					pkgFinished: true,
				}
			}
			continue
		}
		name := testName{
			pkg:  goOutput.Package,
			name: goOutput.Test,
		}
		if test, _, isSubtest := strings.Cut(goOutput.Test, "/"); isSubtest {
			name.name = test
			if goOutput.Action == "output" {
				resultMap[name].logs.WriteString(goOutput.Output)
			}
			continue
		}
		switch goOutput.Action {
		case "start":
			// ignore
		case "run":
			resultMap[name] = &testAttempt{
				name: name,
			}
		case "skip", "pass", "fail":
			resultMap[name].outcome = goOutput.Action
			ch <- resultMap[name]
		case "output":
			test := resultMap[name]
			switch {
			case test.ended:
				// go test attributes a timeout panic to the last resumed
				// test, even if it already passed. Print it so it isn't lost.
				fmt.Print(goOutput.Output)
			case strings.TrimSpace(goOutput.Output) == flakytest.FlakyTestLogMessage:
				test.isMarkedFlaky = true
			default:
				test.logs.WriteString(goOutput.Output)
				test.ended = strings.HasPrefix(goOutput.Output, "--- PASS: "+name.name+" ") ||
					strings.HasPrefix(goOutput.Output, "--- SKIP: "+name.name+" ")
			}
		}
	}
	return cmd.Wait()
}

// isPkgSummary reports whether line is a go test result line for pkg, such as
// "ok  \tpkg\t0.1s". main prints its own summary with the attempt number.
func isPkgSummary(line, pkg string) bool {
	if line == "PASS\n" || line == "FAIL\n" {
		return true
	}
	f := strings.Fields(line)
	return len(f) >= 2 && f[1] == pkg && (f[0] == "ok" || f[0] == "FAIL" || f[0] == "?")
}

func main() {
	ctx := context.Background()

	// We only need to parse the -v flag to figure out whether to print the logs
	// for a test. We don't need to parse any other flags, so we just use the
	// flag package to parse the -v flag and then pass the rest of the args
	// through to 'go test'.
	// We run `go test -json` which returns the same information as `go test -v`,
	// but in a machine-readable format. So this flag is only for testwrapper's
	// output.
	v := flag.Bool("v", false, "verbose")

	flag.Usage = func() {
		fmt.Println("usage: testwrapper [testwrapper-flags] [pattern] [build/test flags & test binary flags]")
		fmt.Println()
		fmt.Println("testwrapper-flags:")
		flag.CommandLine.PrintDefaults()
		fmt.Println()
		fmt.Println("examples:")
		fmt.Println("\ttestwrapper -v ./... -count=1")
		fmt.Println("\ttestwrapper ./pkg/foo -run TestBar -count=1")
		fmt.Println()
		fmt.Println("Unlike 'go test', testwrapper requires a package pattern as the first positional argument and only supports a single pattern.")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		fmt.Println("no pattern specified")
		flag.Usage()
		os.Exit(1)
	} else if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		fmt.Println("expected single pattern")
		flag.Usage()
		os.Exit(1)
	}
	pattern, otherArgs := args[0], args[1:]

	type nextRun struct {
		tests   []*packageTests
		attempt int
	}

	toRun := []*nextRun{
		{
			tests:   []*packageTests{{pattern: pattern}},
			attempt: 1,
		},
	}
	printPkgOutcome := func(pkg, outcome string, attempt int) {
		if outcome == "skip" {
			fmt.Printf("?\t%s [skipped/no tests] \n", pkg)
			return
		}
		if outcome == "pass" {
			outcome = "ok"
		}
		if outcome == "fail" {
			outcome = "FAIL"
		}
		if attempt > 1 {
			fmt.Printf("%s\t%s [attempt=%d]\n", outcome, pkg, attempt)
			return
		}
		fmt.Printf("%s\t%s\n", outcome, pkg)
	}

	for len(toRun) > 0 {
		var thisRun *nextRun
		thisRun, toRun = toRun[0], toRun[1:]

		if thisRun.attempt >= maxAttempts {
			fmt.Println("max attempts reached")
			os.Exit(1)
		}
		if thisRun.attempt > 1 {
			fmt.Printf("\n\nAttempt #%d: Retrying flaky tests:\n\n", thisRun.attempt)
		}

		failed := false
		toRetry := make(map[string][]string) // pkg -> tests to retry
		for _, pt := range thisRun.tests {
			ch := make(chan *testAttempt)
			runErr := make(chan error, 1)
			go func() {
				runErr <- runTests(ctx, thisRun.attempt, pt, otherArgs, ch)
			}()
			retryable := false
			for tr := range ch {
				if tr.pkgFinished {
					if tr.outcome == "fail" && len(toRetry[tr.name.pkg]) == 0 {
						failed = true
					}
					printPkgOutcome(tr.name.pkg, tr.outcome, thisRun.attempt)
					continue
				}
				if *v || tr.outcome == "fail" {
					io.Copy(os.Stdout, &tr.logs)
				}
				if tr.outcome != "fail" {
					continue
				}
				if tr.isMarkedFlaky {
					retryable = true
					toRetry[tr.name.pkg] = append(toRetry[tr.name.pkg], tr.name.name)
				} else {
					failed = true
				}
			}
			if err := <-runErr; err != nil && !retryable {
				log.Printf("go test: %v", err)
				failed = true
			}
		}
		if failed {
			fmt.Println("\n\nNot retrying flaky tests because non-flaky tests failed.")
			os.Exit(1)
		}
		if len(toRetry) == 0 {
			continue
		}
		pkgs := maps.Keys(toRetry)
		sort.Strings(pkgs)
		nextRun := &nextRun{
			attempt: thisRun.attempt + 1,
		}
		for _, pkg := range pkgs {
			tests := toRetry[pkg]
			sort.Strings(tests)
			nextRun.tests = append(nextRun.tests, &packageTests{
				pattern: pkg,
				tests:   tests,
			})
		}
		toRun = append(toRun, nextRun)
	}
}
