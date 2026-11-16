package provider_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The root tenancy package must stay importable without the framework.
//
// hostname, identify, authorize and rls are the parts an application wires
// into middleware, and they are also the parts worth testing exhaustively and
// reusing from a command-line tool or a migration. If the root ever imports
// api/app or orm, every consumer of the resolution logic links the whole
// framework, and the split that makes this package cheap to reason about is
// gone — measured rather than intended, because an import added in the wrong
// file is invisible until somebody profiles a binary.
func TestTheRootPackageDoesNotReachTheFramework(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/lemmego/fieldbubble/tenancy").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "github.com/lemmego/api"),
			strings.HasPrefix(line, "github.com/lemmego/orm"),
			strings.HasPrefix(line, "github.com/lemmego/inertia"):
			t.Errorf("the root tenancy package reaches %s; it must stay framework-free", line)
		}
	}
}

// And the positive half, so the split is measured in both directions rather
// than asserted in one: this package DOES reach the framework, which is the
// whole reason it exists separately.
func TestThisPackageDoesReachTheFramework(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/lemmego/fieldbubble/tenancy/provider").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	if !strings.Contains(string(out), "github.com/lemmego/api/app") {
		t.Error("the provider does not reach api/app, so this test is not measuring what it claims")
	}
}
