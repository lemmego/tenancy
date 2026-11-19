// Package sqlstore resolves a tenant from a SQL table.
//
// It answers the first of the two questions tenancy asks of a Registry —
// "which tenant is this identifier?" — and it scopes the second one without
// answering it. Membership is the application's: which table holds it, and
// what a membership even means for each population of caller, is not
// something a library can know.
//
// # Any database the ORM supports
//
// Resolution is core, so nothing here is one vendor's. The two things that
// differ are configured: how a bind parameter is spelled, and whether the id
// comparison needs a cast. The defaults are PostgreSQL's because that is the
// common case; MySQL and SQLite pass a Placeholder of "?" and IDCast "-".
//
// Scoping the membership check is the EXTENSION, and it is optional for the
// same reason. On PostgreSQL, Config.Scope is rls.Config.SetLocal and the
// membership query needs no tenant predicate because the policy supplies
// one. On a database with no row-level security there is nothing to scope,
// and the membership query carries its own predicate — which it is handed
// the tenant id in order to do.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"

	"github.com/lemmego/tenancy"
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

	// DefaultIDCast is appended to the id comparison, so a text parameter
	// is compared as a uuid rather than relying on PostgreSQL's parameter
	// inference in an expression where it may not apply.
	DefaultIDCast = "::uuid"

	// None turns off a column or a cast that has a default.
	None = "-"
)

// PostgresPlaceholder and QuestionPlaceholder are the two spellings in
// practice: $n for PostgreSQL, ? for MySQL and SQLite.
func PostgresPlaceholder(n int) string { return "$" + strconv.Itoa(n) }
func QuestionPlaceholder(int) string   { return "?" }

// Execer is anything that can run a statement — a *sql.DB, a *sql.Tx.
//
// An alias rather than a definition, deliberately: Go compares function
// parameter types by identity, and an alias to an unnamed interface stays
// identical to that literal. So rls.Config.SetLocal, whose parameter is
// written out longhand, is directly assignable to Config.Scope without a
// wrapper at every call site.
type Execer = interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

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

	// Placeholder renders the nth bind parameter, counting from one.
	// Defaults to PostgreSQL's $n.
	Placeholder func(int) string

	// IDCast is appended to the id comparison. Blank takes DefaultIDCast;
	// None means no cast, which is what MySQL and SQLite want.
	IDCast string

	// Scope binds the tenant for the duration of the membership check.
	//
	// Optional, because it is the extension rather than the core. With it —
	// rls.Config.SetLocal on PostgreSQL — the Members query needs no tenant
	// predicate, because the policy supplies one and a query that stated it
	// twice would hide whether the policy works. Without it, Members MUST
	// filter by the tenant id it is handed, because nothing else will.
	Scope func(ctx context.Context, exec Execer, tenantID string) error

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
	if c.Placeholder == nil {
		c.Placeholder = PostgresPlaceholder
	}
	if c.IDCast == "" {
		c.IDCast = DefaultIDCast
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
var ErrNoMembershipQuery = errors.New("sqlstore: no membership query configured")

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
	if s.cfg.SoftDeleteColumn != None {
		live = " AND " + s.cfg.SoftDeleteColumn + " IS NULL"
	}

	bind := s.cfg.Placeholder(1)
	cast := s.cfg.IDCast
	if cast == None {
		cast = ""
	}

	var where string
	switch id.Kind {
	case tenancy.KindSlug:
		where = "lower(" + s.cfg.SlugColumn + ") = lower(" + bind + ")"
	case tenancy.KindID:
		where = s.cfg.IDColumn + " = " + bind + cast
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
		return tenancy.Tenant{}, fmt.Errorf("sqlstore: resolving tenant: %w", err)
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
		return false, fmt.Errorf("sqlstore: membership check: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Only when the extension is configured. Without it the membership
	// query filters itself — see Config.Scope.
	if s.cfg.Scope != nil {
		if err := s.cfg.Scope(ctx, tx, tenantID); err != nil {
			return false, fmt.Errorf("sqlstore: scoping the membership check: %w", err)
		}
	}

	member, err := s.cfg.Members(ctx, tx, tenantID, principal)
	if err != nil {
		return false, fmt.Errorf("sqlstore: membership check: %w", err)
	}
	return member, nil
}
