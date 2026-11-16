package tenancy

import (
	"context"
	"errors"
	"testing"
)

// A registry over two workspaces. ada belongs to acme only.
type fakeRegistry struct {
	workspaces []Workspace
	members    map[string][]string // workspace id -> principal keys
	lookups    int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{
		workspaces: []Workspace{
			{ID: "11111111-1111-1111-1111-111111111111", Slug: "acme", Name: "Acme", Status: StatusActive},
			{ID: "22222222-2222-2222-2222-222222222222", Slug: "globex", Name: "Globex", Status: StatusActive},
			{ID: "33333333-3333-3333-3333-333333333333", Slug: "dormant", Name: "Dormant", Status: StatusSuspended},
		},
		members: map[string][]string{
			"11111111-1111-1111-1111-111111111111": {"ada"},
			"22222222-2222-2222-2222-222222222222": {"grace"},
		},
	}
}

func (f *fakeRegistry) Lookup(_ context.Context, id Identifier) (Workspace, error) {
	f.lookups++
	for _, w := range f.workspaces {
		if (id.Kind == KindSlug && w.Slug == id.Value) || (id.Kind == KindID && w.ID == id.Value) {
			return w, nil
		}
	}
	return Workspace{}, ErrNoWorkspace
}

func (f *fakeRegistry) IsMember(_ context.Context, workspaceID string, p Principal) (bool, error) {
	for _, key := range f.members[workspaceID] {
		if key == p.PrincipalKey() {
			return true, nil
		}
	}
	return false, nil
}

type user string

func (u user) PrincipalKind() string { return "user" }
func (u user) PrincipalKey() string  { return string(u) }

func headerIdent(value string, kind Kind) Identification {
	return Identification{Workspace: Identifier{Kind: kind, Value: value, Source: SourceHeader}}
}

// THE test. A header is a string from the internet; membership is what makes
// it safe.
func TestAHeaderNamingAnotherWorkspaceIsRefused(t *testing.T) {
	reg := newFakeRegistry()

	// ada is a member of acme. She asks for globex by slug, and by uuid.
	for name, ident := range map[string]Identification{
		"by slug": headerIdent("globex", KindSlug),
		"by uuid": headerIdent("22222222-2222-2222-2222-222222222222", KindID),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Authorize(context.Background(), reg, ident, user("ada"))
			if !errors.Is(err, ErrNoWorkspace) {
				t.Fatalf("want ErrNoWorkspace, got %v", err)
			}
		})
	}
}

// And the refusal must be indistinguishable from "no such workspace", or the
// error is an oracle for which companies are customers.
func TestARefusalLooksTheSameAsANonexistentWorkspace(t *testing.T) {
	reg := newFakeRegistry()
	ctx := context.Background()

	_, notMine := Authorize(ctx, reg, headerIdent("globex", KindSlug), user("ada"))
	_, notReal := Authorize(ctx, reg, headerIdent("nosuchco", KindSlug), user("ada"))

	if notMine == nil || notReal == nil {
		t.Fatal("both must be refused")
	}
	if notMine.Error() != notReal.Error() {
		t.Fatalf("the errors differ, which enumerates the tenant list:\n  not mine: %v\n  not real: %v",
			notMine, notReal)
	}
}

func TestAMemberIsBoundToTheWorkspaceTheRegistryResolved(t *testing.T) {
	reg := newFakeRegistry()
	binding, err := Authorize(context.Background(), reg, headerIdent("acme", KindSlug), user("ada"))
	if err != nil {
		t.Fatal(err)
	}
	// The binding carries the resolved uuid, not the string from the header.
	if binding.Workspace.ID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("binding = %+v", binding)
	}
	if binding.Source != SourceHeader {
		t.Fatalf("source = %v, want header so the cache keys it separately", binding.Source)
	}
}

// A header with nobody authenticated behind it is just a string.
func TestAHeaderNamedWorkspaceNeedsAPrincipal(t *testing.T) {
	reg := newFakeRegistry()
	_, err := Authorize(context.Background(), reg, headerIdent("acme", KindSlug), nil)
	if !errors.Is(err, ErrNoPrincipal) {
		t.Fatalf("want ErrNoPrincipal, got %v", err)
	}
}

// But a host-named workspace resolves for an anonymous visitor, who has to be
// able to reach the sign-in page.
func TestAHostNamedWorkspaceResolvesForAnAnonymousVisitor(t *testing.T) {
	reg := newFakeRegistry()
	ident := Identification{Workspace: Identifier{Kind: KindSlug, Value: "acme", Source: SourceHost}}
	binding, err := Authorize(context.Background(), reg, ident, nil)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Workspace.Slug != "acme" {
		t.Fatalf("binding = %+v", binding)
	}
}

func TestASuspendedWorkspaceDoesNotServe(t *testing.T) {
	reg := newFakeRegistry()
	ident := Identification{Workspace: Identifier{Kind: KindSlug, Value: "dormant", Source: SourceHost}}
	_, err := Authorize(context.Background(), reg, ident, nil)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

// A delinquent workspace still signs in; billing redirects it later. If this
// ever returns ErrUnavailable, an unpaid customer cannot reach the page that
// takes their money.
func TestADelinquentWorkspaceStillServes(t *testing.T) {
	if !StatusDelinquent.Serves() {
		t.Fatal("a delinquent workspace must still serve, or it cannot reach its billing page")
	}
	if StatusSuspended.Serves() || StatusArchived.Serves() {
		t.Fatal("suspended and archived must not serve")
	}
}

// The deferred uuid comparison from Identify is settled here, and a
// contradiction is refused rather than resolved in anyone's favour.
func TestAContradictoryIDHeaderIsRefused(t *testing.T) {
	reg := newFakeRegistry()
	ident := Identification{Workspace: Identifier{
		Kind:          KindSlug,
		Value:         "acme",
		Source:        SourceHost,
		MustAgreeWith: "22222222-2222-2222-2222-222222222222", // globex
	}}
	if _, err := Authorize(context.Background(), reg, ident, user("ada")); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}

	// Agreement passes.
	ident.Workspace.MustAgreeWith = "11111111-1111-1111-1111-111111111111"
	if _, err := Authorize(context.Background(), reg, ident, user("ada")); err != nil {
		t.Fatalf("agreement should pass: %v", err)
	}
}

func TestNamingNoWorkspaceIsRefused(t *testing.T) {
	reg := newFakeRegistry()
	if _, err := Authorize(context.Background(), reg, Identification{}, user("ada")); !errors.Is(err, ErrNoWorkspace) {
		t.Fatalf("want ErrNoWorkspace, got %v", err)
	}
}
