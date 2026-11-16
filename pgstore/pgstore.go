// Package pgstore answers the two questions tenancy asks of a registry,
// against PostgreSQL.
//
// Lookup resolves a slug or a uuid to a workspace. IsMember says whether a
// caller belongs to it. Between them they turn a client-supplied workspace
// header into something safe to scope a request by.
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lemmego/fieldbubble/tenancy"
	"github.com/lemmego/fieldbubble/tenancy/rls"
)

// Store reads the workspace registry.
type Store struct {
	db *sql.DB
}

// New returns a store over an ordinary pool.
//
// The pool should be the application's own, connected as the unprivileged
// application role — the same one every request uses. Nothing here needs to
// bypass row-level security, which is deliberate: see IsMember.
func New(db *sql.DB) *Store { return &Store{db: db} }

var _ tenancy.Registry = (*Store)(nil)

// Lookup resolves an identifier to a workspace.
//
// workspaces is the tenant table itself, so it carries no row-level security
// policy and is readable without a workspace in scope — which it has to be,
// since resolving the workspace is what establishes the scope.
//
// The slug comparison is lower(slug) to match the partial unique index the
// migration creates, so this is an index scan rather than a sequential one.
func (s *Store) Lookup(ctx context.Context, id tenancy.Identifier) (tenancy.Workspace, error) {
	var (
		query string
		arg   any
	)
	switch id.Kind {
	case tenancy.KindSlug:
		query = `SELECT id, slug, name, status FROM workspaces
		          WHERE lower(slug) = lower($1) AND deleted_at IS NULL`
		arg = id.Value
	case tenancy.KindID:
		query = `SELECT id, slug, name, status FROM workspaces
		          WHERE id = $1::uuid AND deleted_at IS NULL`
		arg = id.Value
	default:
		return tenancy.Workspace{}, tenancy.ErrNoWorkspace
	}

	var workspace tenancy.Workspace
	var status string
	err := s.db.QueryRowContext(ctx, query, arg).
		Scan(&workspace.ID, &workspace.Slug, &workspace.Name, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return tenancy.Workspace{}, tenancy.ErrNoWorkspace
	case err != nil:
		// Deliberately NOT folded into ErrNoWorkspace. A database that is
		// down must not look like a workspace that does not exist: one is a
		// 503 and the other a 404, and reporting the wrong one turns an
		// outage into a mystery about missing tenants.
		return tenancy.Workspace{}, fmt.Errorf("pgstore: resolving workspace: %w", err)
	}
	workspace.Status = tenancy.Status(status)
	return workspace, nil
}

// IsMember reports whether the principal belongs to the workspace.
//
// # Why this opens its own transaction
//
// users is tenant-scoped and carries a row-level security policy, so a query
// run with no workspace in scope sees nothing — and a membership check that
// always answers "no" is a login that always fails. The obvious fix is to run
// this through a role that bypasses the policy, and that is the wrong fix: it
// would put a BYPASSRLS connection on the authentication path of every single
// request, which is the one place it must never be.
//
// So the check scopes itself to the workspace being asked about. That is both
// correct and the narrowest possible claim: the question is "is this caller in
// workspace X", so looking only inside workspace X is exactly right, and the
// answer cannot be influenced by rows outside it.
//
// The transaction is read-only and short. It costs one round trip before the
// request's own transaction opens, which is the price of not caching yet; the
// cache goes in front of this, not inside it.
func (s *Store) IsMember(ctx context.Context, workspaceID string, principal tenancy.Principal) (bool, error) {
	if principal == nil {
		return false, nil
	}

	query, err := membershipQuery(principal.PrincipalKind())
	if err != nil {
		return false, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, fmt.Errorf("pgstore: membership check: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := rls.SetLocal(ctx, tx, workspaceID); err != nil {
		return false, fmt.Errorf("pgstore: scoping the membership check: %w", err)
	}

	var exists bool
	if err := tx.QueryRowContext(ctx, query, principal.PrincipalKey()).Scan(&exists); err != nil {
		return false, fmt.Errorf("pgstore: membership check: %w", err)
	}
	return exists, nil
}

// membershipQuery is one query per population.
//
// An unrecognised kind is an error and not a quiet false. A quiet false would
// mean that adding a new kind of caller — a device token, a service account —
// produces an application where that caller can authenticate and then belongs
// to nothing, which presents as a baffling permission problem rather than as
// the missing implementation it is.
func membershipQuery(kind string) (string, error) {
	switch kind {
	case "user":
		// No workspace_id predicate, and that is the point: the transaction
		// is already scoped, so the policy supplies it. Writing it here as
		// well would work, and would also hide whether the policy is doing
		// anything — a test asserting isolation would then pass with the
		// policy removed.
		return `SELECT EXISTS (
		          SELECT 1 FROM users
		           WHERE id = $1::bigint AND active AND deleted_at IS NULL)`, nil
	default:
		return "", fmt.Errorf("pgstore: no membership rule for principal kind %q", kind)
	}
}
