package provider_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The root tenancy package must stay importable without the framework.
//
// hostname, identify, authorize, rls and pgstore are the parts an application
// wires into middleware, and they are also the parts worth testing
// exhaustively and reusing from a command-line tool or a migration. If any of
// them imports api/app or orm, every consumer of the resolution logic links
// the whole framework, and the split that makes this package cheap to reason
// about is gone — measured rather than intended, because an import added in
// the wrong file is invisible until somebody profiles a binary.
//
// rls's own test DOES import orm, to assert the two writers of the
// tenant-binding statement agree. A test binary is not a consumer's build,
// which is why that is a test file and not an import.
func TestTheRootPackageDoesNotReachTheFramework(t *testing.T) {
	// Every package but the provider. rls is reached from a migration and
	// pgstore from a registry, and neither has any business linking the
	// framework — a migration that pulls in api/app pulls in a web server.
	for _, pkg := range []string{
		"github.com/lemmego/tenancy",
		"github.com/lemmego/tenancy/hostname",
		"github.com/lemmego/tenancy/rls",
		"github.com/lemmego/tenancy/sqlstore",
	} {
		out, err := exec.Command("go", "list", "-deps", pkg).Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			switch {
			case strings.HasPrefix(line, "github.com/lemmego/api"),
				strings.HasPrefix(line, "github.com/lemmego/orm"),
				strings.HasPrefix(line, "github.com/lemmego/inertia"):
				t.Errorf("%s reaches %s; it must stay framework-free", pkg, line)
			}
		}
	}
}

// And the positive half, so the split is measured in both directions rather
// than asserted in one: this package DOES reach the framework, which is the
// whole reason it exists separately.
func TestThisPackageDoesReachTheFramework(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/lemmego/tenancy/provider").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	if !strings.Contains(string(out), "github.com/lemmego/api/app") {
		t.Error("the provider does not reach api/app, so this test is not measuring what it claims")
	}
}
