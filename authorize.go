package tenancy

import (
	"context"
	"errors"
	"fmt"
)

// Turning "which tenant is this request about" into "which tenant may
// this request touch".
//
// Identify answers the first question from the host and the headers. It
// cannot answer the second, because a header is client-supplied: a request
// that says X-Tenant-User: globex has merely said a word. Authorize is
// what makes that word safe, and the rule it enforces is one sentence:
//
//	The binding comes from the caller's MEMBERSHIP of the named tenant,
//	never from the name itself.
//
// So a member of acme who names globex is refused — and refused with the same
// error as somebody who names a tenant that does not exist, because a
// distinct "forbidden" would confirm that globex is a customer of ours.
//
// This is the layer that would have been missing if the tenant were simply
// read from a header and handed to the query scope. Both the ORM predicate
// and the row-level security policy would then have enforced the attacker's
// choice, perfectly and silently.

// Status is a tenant's lifecycle state.
type Status string

const (
	StatusProvisioning Status = "provisioning"
	StatusActive       Status = "active"
	StatusSuspended    Status = "suspended"
	StatusDelinquent   Status = "delinquent"
	StatusArchived     Status = "archived"
)

// Serves reports whether a tenant in this state answers ordinary requests.
// Delinquent does: an unpaid tenant still signs in, and is funnelled to
// its billing page by a later middleware rather than disappearing.
func (s Status) Serves() bool {
	return s == StatusActive || s == StatusDelinquent || s == StatusProvisioning
}

// Tenant is the registry's answer, and carries scalars only.
//
// Deliberately not a model and never a database handle: this value is cached,
// and a cache holding something with methods and a connection is a cache that
// one day deserialises into a surprise.
type Tenant struct {
	ID     string // uuid, and the authoritative identifier
	Slug   string
	Name   string
	Status Status
}

// Principal is whoever is making the request, as the identity layer sees
// them. Opaque here on purpose: this package must not learn what a password
// is, or whether the caller is a person, a device or a machine token.
type Principal interface {
	// PrincipalKind says which population the caller belongs to: "user" for
	// a member of a tenant, "superuser" for a customer on the console,
	// "sysadmin" for platform staff.
	//
	// It exists because membership means a different query for each, and
	// because a bare key would otherwise be ambiguous: user 42 and superuser
	// 42 are different people, and a store that compared only the key would
	// one day treat them as the same.
	PrincipalKind() string

	// PrincipalKey identifies the caller within that population.
	PrincipalKey() string
}

// Registry resolves identifiers and memberships. The application supplies it;
// this package defines only the shape, so tenancy never imports identity.
type Registry interface {
	// Lookup resolves a slug or a uuid to a tenant.
	Lookup(ctx context.Context, id Identifier) (Tenant, error)

	// IsMember reports whether the principal belongs to the tenant.
	//
	// A bool and not a membership record, because that is the entire
	// question Authorize asks, and a narrow seam is one the application
	// cannot accidentally answer with something expensive.
	IsMember(ctx context.Context, tenantID string, principal Principal) (bool, error)
}

var (
	// ErrNoTenant means the named tenant does not exist, or the caller
	// is not a member of it. One error for both, on purpose: see Authorize.
	ErrNoTenant = errors.New("tenancy: no such tenant")

	// ErrUnavailable means the tenant exists but is not serving requests.
	ErrUnavailable = errors.New("tenancy: tenant is not available")

	// ErrNoPrincipal means a tenant was named by a header with nobody
	// authenticated to vouch for it.
	ErrNoPrincipal = errors.New("tenancy: a tenant was named by an unauthenticated request")
)

// Binding is the authorised result: the one value every query, every policy
// and every cache key for this request is scoped by.
type Binding struct {
	Tenant Tenant

	// Source records how the tenant was named, so the cache can key each
	// source separately. Conflating a host-resolved and a header-resolved
	// entry means one can poison the other, which is a tenant leak rather
	// than a cache bug.
	Source Source
}

// Authorize resolves an identification into a binding, or refuses it.
//
// principal may be nil, which is the unauthenticated case. A host-named
// tenant is still resolved then — an anonymous visitor must be able to
// reach acme's sign-in page — but a HEADER-named tenant is refused,
// because a header with nobody behind it is just a string from the internet.
// Select resolves an identifier to a tenant WITHOUT authorising it.
//
// This is the half that can run before authentication, and splitting it out
// is not a tidying: a request's tenant has to be known before the
// application can look up the user, because the users table is scoped to a
// tenant and a lookup with none finds nobody. Authorize cannot be moved
// earlier to fix that — it needs a principal, which is what the lookup is
// for — so the resolution happens first and the authorisation still happens
// after, with nothing bound in between.
//
// Selecting is not granting. Nothing may be read or written on the strength
// of a Select: it answers "which tenant is this request about", and
// Confirm answers "may this caller have it".
func Select(ctx context.Context, reg Registry, ident Identification) (Tenant, error) {
	if ident.Tenant.IsZero() {
		return Tenant{}, ErrNoTenant
	}
	return reg.Lookup(ctx, ident.Tenant)
}

// Confirm authorises an already-selected tenant for a principal.
func Confirm(ctx context.Context, reg Registry, tenant Tenant, ident Identification, principal Principal) (Binding, error) {
	if ident.Tenant.Source == SourceHeader && principal == nil {
		return Binding{}, ErrNoPrincipal
	}

	// A uuid header on a tenant host could not be compared without the
	// lookup, so the comparison happens here. Disagreement is refused rather
	// than resolved in the host's favour: the client has contradicted itself
	// and the safe reading of a contradiction is neither branch.
	if want := ident.Tenant.MustAgreeWith; want != "" && tenant.ID != want {
		// The header is not named: Confirm has no business knowing what the
		// application called it, and the request's own log line carries it.
		return Binding{}, fmt.Errorf("%w: the host resolves to %s and the id header says %s",
			ErrAmbiguous, tenant.ID, want)
	}

	if !tenant.Status.Serves() {
		return Binding{}, fmt.Errorf("%w: %s is %s", ErrUnavailable, tenant.Slug, tenant.Status)
	}

	// The check that makes a client-supplied identifier safe.
	//
	// Note what is NOT done here: the binding is not taken from
	// ident.Tenant.Value. It is taken from the tenant the registry
	// resolved AND confirmed a membership in, so the only way to be bound to
	// a tenant is to belong to it.
	if principal != nil {
		member, err := reg.IsMember(ctx, tenant.ID, principal)
		if err != nil {
			return Binding{}, err
		}
		if !member {
			// Deliberately ErrNoTenant and not a distinct "forbidden".
			// A different error for "exists but not yours" is an oracle: it
			// confirms which companies are customers, and lets anybody
			// enumerate the tenant list from a login page.
			return Binding{}, ErrNoTenant
		}
	}

	return Binding{Tenant: tenant, Source: ident.Tenant.Source}, nil
}

// Authorize resolves an identifier and authorises it in one step.
//
// Select followed by Confirm. Callers that have already selected — because
// they had to, in order to find the user — call Confirm directly rather than
// paying for a second lookup.
func Authorize(ctx context.Context, reg Registry, ident Identification, principal Principal) (Binding, error) {
	if ident.Tenant.IsZero() {
		return Binding{}, ErrNoTenant
	}
	if ident.Tenant.Source == SourceHeader && principal == nil {
		return Binding{}, ErrNoPrincipal
	}

	tenant, err := Select(ctx, reg, ident)
	if err != nil {
		return Binding{}, err
	}
	return Confirm(ctx, reg, tenant, ident, principal)
}
