package tenancy

import (
	"context"
	"errors"
	"fmt"
)

// Turning "which workspace is this request about" into "which workspace may
// this request touch".
//
// Identify answers the first question from the host and the headers. It
// cannot answer the second, because a header is client-supplied: a request
// that says X-Workspace-User: globex has merely said a word. Authorize is
// what makes that word safe, and the rule it enforces is one sentence:
//
//	The binding comes from the caller's MEMBERSHIP of the named workspace,
//	never from the name itself.
//
// So a member of acme who names globex is refused — and refused with the same
// error as somebody who names a workspace that does not exist, because a
// distinct "forbidden" would confirm that globex is a customer of ours.
//
// This is the layer that would have been missing if the tenant were simply
// read from a header and handed to the query scope. Both the ORM predicate
// and the row-level security policy would then have enforced the attacker's
// choice, perfectly and silently.

// Status is a workspace's lifecycle state.
type Status string

const (
	StatusProvisioning Status = "provisioning"
	StatusActive       Status = "active"
	StatusSuspended    Status = "suspended"
	StatusDelinquent   Status = "delinquent"
	StatusArchived     Status = "archived"
)

// Serves reports whether a workspace in this state answers ordinary requests.
// Delinquent does: an unpaid workspace still signs in, and is funnelled to
// its billing page by a later middleware rather than disappearing.
func (s Status) Serves() bool {
	return s == StatusActive || s == StatusDelinquent || s == StatusProvisioning
}

// Workspace is the registry's answer, and carries scalars only.
//
// Deliberately not a model and never a database handle: this value is cached,
// and a cache holding something with methods and a connection is a cache that
// one day deserialises into a surprise.
type Workspace struct {
	ID     string // uuid, and the authoritative identifier
	Slug   string
	Name   string
	Status Status
}

// Principal is whoever is making the request, as the identity layer sees
// them. Opaque here on purpose: this package must not learn what a password
// is, or whether the caller is a person, a device or a machine token.
type Principal interface {
	// PrincipalKey identifies the caller within one workspace. Two different
	// strings are two different callers.
	PrincipalKey() string
}

// Registry resolves identifiers and memberships. The application supplies it;
// this package defines only the shape, so tenancy never imports identity.
type Registry interface {
	// Lookup resolves a slug or a uuid to a workspace.
	Lookup(ctx context.Context, id Identifier) (Workspace, error)

	// IsMember reports whether the principal belongs to the workspace.
	//
	// A bool and not a membership record, because that is the entire
	// question Authorize asks, and a narrow seam is one the application
	// cannot accidentally answer with something expensive.
	IsMember(ctx context.Context, workspaceID string, principal Principal) (bool, error)
}

var (
	// ErrNoWorkspace means the named workspace does not exist, or the caller
	// is not a member of it. One error for both, on purpose: see Authorize.
	ErrNoWorkspace = errors.New("tenancy: no such workspace")

	// ErrUnavailable means the workspace exists but is not serving requests.
	ErrUnavailable = errors.New("tenancy: workspace is not available")

	// ErrNoPrincipal means a workspace was named by a header with nobody
	// authenticated to vouch for it.
	ErrNoPrincipal = errors.New("tenancy: a workspace was named by an unauthenticated request")
)

// Binding is the authorised result: the one value every query, every policy
// and every cache key for this request is scoped by.
type Binding struct {
	Workspace Workspace

	// Source records how the workspace was named, so the cache can key each
	// source separately. Conflating a host-resolved and a header-resolved
	// entry means one can poison the other, which is a tenant leak rather
	// than a cache bug.
	Source Source
}

// Authorize resolves an identification into a binding, or refuses it.
//
// principal may be nil, which is the unauthenticated case. A host-named
// workspace is still resolved then — an anonymous visitor must be able to
// reach acme's sign-in page — but a HEADER-named workspace is refused,
// because a header with nobody behind it is just a string from the internet.
func Authorize(ctx context.Context, reg Registry, ident Identification, principal Principal) (Binding, error) {
	if ident.Workspace.IsZero() {
		return Binding{}, ErrNoWorkspace
	}

	if ident.Workspace.Source == SourceHeader && principal == nil {
		return Binding{}, ErrNoPrincipal
	}

	workspace, err := reg.Lookup(ctx, ident.Workspace)
	if err != nil {
		return Binding{}, err
	}

	// A uuid header on a workspace host could not be compared without this
	// lookup, so the comparison happens here. Disagreement is refused rather
	// than resolved in the host's favour: the client has contradicted itself
	// and the safe reading of a contradiction is neither branch.
	if want := ident.Workspace.MustAgreeWith; want != "" && workspace.ID != want {
		return Binding{}, fmt.Errorf("%w: host resolves to %s, %s says %s",
			ErrAmbiguous, workspace.ID, HeaderID, want)
	}

	if !workspace.Status.Serves() {
		return Binding{}, fmt.Errorf("%w: %s is %s", ErrUnavailable, workspace.Slug, workspace.Status)
	}

	// The check that makes a client-supplied identifier safe.
	//
	// Note what is NOT done here: the binding is not taken from
	// ident.Workspace.Value. It is taken from the workspace the registry
	// resolved AND confirmed a membership in, so the only way to be bound to
	// a workspace is to belong to it.
	if principal != nil {
		member, err := reg.IsMember(ctx, workspace.ID, principal)
		if err != nil {
			return Binding{}, err
		}
		if !member {
			// Deliberately ErrNoWorkspace and not a distinct "forbidden".
			// A different error for "exists but not yours" is an oracle: it
			// confirms which companies are customers, and lets anybody
			// enumerate the tenant list from a login page.
			return Binding{}, ErrNoWorkspace
		}
	}

	return Binding{Workspace: workspace, Source: ident.Workspace.Source}, nil
}
