// Package pgstore resolves a tenant from a PostgreSQL table.
//
// It answers the first of the two questions tenancy asks of a Registry —
// "which tenant is this identifier?" — and it scopes the second one without
// answering it. Membership is the application's: which table holds it, and
// what a membership even means for each population of caller, is not
// something a library can know.
//
// What this package does own is the part that is easy to get wrong. See
// IsMember.
package pgstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lemmego/tenancy"
	"github.com/lemmego/tenancy/rls"
)

// Defaults for the tenant table's name and columns.
const (
	DefaultTable        = "tenants"
	DefaultIDColumn     = "id"
	DefaultSlugColumn   = "slug"
	DefaultNameColumn   = "name"
	DefaultStatusColumn = "status"

	// DefaultSoftDeleteColumn is excluded from every lookup. Set
	// Config.SoftDeleteColumn to "-" if the table has none.
	DefaultSoftDeleteColumn = "deleted_at"
)

// MemberFunc answers whether a principal belongs to a tenant.
//
// It is handed a transaction that is **already scoped to that tenant**, so a
// query inside it needs no tenant predicate of its own and cannot see another
// tenant's rows. That is the whole reason this is a callback rather than an
// interface the application implements from scratch: the scoping is the
// subtle half, and it belongs here.
type MemberFunc func(ctx context.Context, tx *sql.Tx, tenantID string, principal tenancy.Principal) (bool, error)

// Config names the tenant table and supplies the membership query.
type Config struct {
	Table            string
	IDColumn         string
	SlugColumn       string
	NameColumn       string
	StatusColumn     string
	SoftDeleteColumn string

	// RLS is the row-level security configuration, used to scope the
	// membership check.
	RLS rls.Config

	// Members is the application's membership query. Required by IsMember;
	// without it IsMember reports an error rather than answering no, because
	// "nobody is a member of anything" is a sign-in that always fails and
	// looks like a permissions bug.
	Members MemberFunc
}

// WithDefaults fills in whatever the caller left blank.
func (c Config) WithDefaults() Config {
	if c.Table == "" {
		c.Table = DefaultTable
	}
	if c.IDColumn == "" {
		c.IDColumn = DefaultIDColumn
	}
	if c.SlugColumn == "" {
		c.SlugColumn = DefaultSlugColumn
	}
	if c.NameColumn == "" {
		c.NameColumn = DefaultNameColumn
	}
	if c.StatusColumn == "" {
		c.StatusColumn = DefaultStatusColumn
	}
	if c.SoftDeleteColumn == "" {
		c.SoftDeleteColumn = DefaultSoftDeleteColumn
	}
	return c
}

// Store reads the tenant registry.
type Store struct {
	db  *sql.DB
	cfg Config
}

// New returns a store over an ordinary pool.
//
// The pool should be the application's own — connected as the unprivileged
// role every request uses. Nothing here needs to bypass row-level security,
// which is deliberate: see IsMember.
func New(db *sql.DB, cfg Config) *Store {
	return &Store{db: db, cfg: cfg.WithDefaults()}
}

var _ tenancy.Registry = (*Store)(nil)

// ErrNoMembershipQuery means Config.Members was not supplied.
var ErrNoMembershipQuery = errors.New("pgstore: no membership query configured")

// Lookup resolves an identifier to a tenant.
//
// The tenant table is the registry itself, so it carries no row-level
// security policy and is readable with no tenant in scope — which it has to
// be, since resolving the tenant is what establishes the scope.
//
// The slug comparison is lower(slug), to match the partial unique index a
// tenant table should carry, so this is an index scan rather than a
// sequential one.
func (s *Store) Lookup(ctx context.Context, id tenancy.Identifier) (tenancy.Tenant, error) {
	columns := fmt.Sprintf("%s, %s, %s, %s",
		s.cfg.IDColumn, s.cfg.SlugColumn, s.cfg.NameColumn, s.cfg.StatusColumn)
	live := ""
	if s.cfg.SoftDeleteColumn != "-" {
		live = " AND " + s.cfg.SoftDeleteColumn + " IS NULL"
	}

	var where string
	switch id.Kind {
	case tenancy.KindSlug:
		where = "lower(" + s.cfg.SlugColumn + ") = lower($1)"
	case tenancy.KindID:
		where = s.cfg.IDColumn + " = $1::uuid"
	default:
		return tenancy.Tenant{}, tenancy.ErrNoTenant
	}

	var tenant tenancy.Tenant
	var status string
	err := s.db.QueryRowContext(ctx,
		"SELECT "+columns+" FROM "+s.cfg.Table+" WHERE "+where+live, id.Value).
		Scan(&tenant.ID, &tenant.Slug, &tenant.Name, &status)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return tenancy.Tenant{}, tenancy.ErrNoTenant
	case err != nil:
		// Deliberately NOT folded into ErrNoTenant. A database that is down
		// must not look like a tenant that does not exist: one is a 503 and
		// the other a 404, and reporting the wrong one turns an outage into a
		// mystery about missing customers.
		return tenancy.Tenant{}, fmt.Errorf("pgstore: resolving tenant: %w", err)
	}
	tenant.Status = tenancy.Status(status)
	return tenant, nil
}

// IsMember reports whether the principal belongs to the tenant.
//
// # Why this opens its own transaction
//
// A membership table is tenant-scoped and carries a row-level security
// policy, so a query run with no tenant in scope sees nothing — and a
// membership check that always answers "no" is a sign-in that always fails.
// The obvious fix is to run it through a role that bypasses the policy, and
// that is the wrong fix: it would put a BYPASSRLS connection on the
// authentication path of every single request, which is the one place it must
// never be.
//
// So the check scopes itself to the tenant being asked about. That is both
// correct and the narrowest possible claim: the question is "is this caller in
// tenant X", so looking only inside tenant X is exactly right, and the answer
// cannot be influenced by rows outside it.
//
// The transaction is read-only and short. It costs one round trip before the
// request's own transaction opens, which is the price of not caching yet; a
// cache goes in front of this, not inside it.
func (s *Store) IsMember(ctx context.Context, tenantID string, principal tenancy.Principal) (bool, error) {
	if principal == nil {
		return false, nil
	}
	if s.cfg.Members == nil {
		return false, ErrNoMembershipQuery
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return false, fmt.Errorf("pgstore: membership check: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := s.cfg.RLS.SetLocal(ctx, tx, tenantID); err != nil {
		return false, fmt.Errorf("pgstore: scoping the membership check: %w", err)
	}

	member, err := s.cfg.Members(ctx, tx, tenantID, principal)
	if err != nil {
		return false, fmt.Errorf("pgstore: membership check: %w", err)
	}
	return member, nil
}
