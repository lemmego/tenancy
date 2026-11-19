package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/lemmego/tenancy"
	"github.com/lemmego/tenancy/rls"
	"github.com/lemmego/tenancy/sqlstore"
)

// This suite builds its own schema.
//
// The version it replaces read an application's `tenants` and `users` tables,
// which is what a package extracted from one application looks like before
// anybody asks it to work in another. Creating the fixture here costs forty
// lines and buys two things: the suite runs against any PostgreSQL, and the
// membership query can deliberately omit a tenant predicate — so the test
// proves this package scopes it rather than assuming so.
//
//	TENANCY_OWNER_DSN  a role that can create tables and owns them
//	TENANCY_APP_DSN    the unprivileged role the store connects as
//
// Both unset skips. A suite that skips and a suite that passes share an exit
// code, so the skip says what is unverified.
const (
	membersTable = "sqlstore_members"
	tenantsTable = "sqlstore_tenants"
)

// security is the extension this suite also exercises: PostgreSQL scoping,
// so the membership query below can omit a tenant predicate.
var security = rls.Config{Setting: "sqlstore_test.tenant_id", Column: "tenant_id"}

func config(members sqlstore.MemberFunc) sqlstore.Config {
	return sqlstore.Config{
		Table:   tenantsTable,
		Scope:   security.SetLocal,
		Members: members,
	}
}

// membersOf answers from the fixture table, with NO tenant predicate.
//
// That omission is the assertion. The transaction this runs in has already
// been scoped by pgstore, so the policy supplies the predicate; if it did not,
// every caller would be a member of every tenant and the cross-tenant test
// below would fail.
func membersOf(ctx context.Context, tx *sql.Tx, _ string, principal tenancy.Principal) (bool, error) {
	var exists bool
	err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM `+membersTable+`
		                 WHERE user_id = $1 AND active)`, principal.PrincipalKey()).Scan(&exists)
	return exists, err
}

type principal struct{ kind, key string }

func (p principal) PrincipalKind() string { return p.kind }
func (p principal) PrincipalKey() string  { return p.key }

type fixture struct {
	store            *sqlstore.Store
	owner            *sql.DB
	acmeID, globexID string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ownerDSN, appDSN := os.Getenv("TENANCY_OWNER_DSN"), os.Getenv("TENANCY_APP_DSN")
	if ownerDSN == "" || appDSN == "" {
		t.Skip("TENANCY_OWNER_DSN and TENANCY_APP_DSN are unset, so the membership path is unverified")
	}

	owner, err := sql.Open("postgres", ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })
	if err := owner.Ping(); err != nil {
		t.Fatalf("TENANCY_OWNER_DSN: %v", err)
	}

	app, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })

	ctx := context.Background()
	drop := func() {
		_, _ = owner.Exec(`DROP TABLE IF EXISTS ` + membersTable)
		_, _ = owner.Exec(`DROP TABLE IF EXISTS ` + tenantsTable)
	}
	drop()
	t.Cleanup(drop)

	if _, err := owner.ExecContext(ctx, `
		CREATE EXTENSION IF NOT EXISTS pgcrypto;
		CREATE TABLE `+tenantsTable+` (
			id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			slug       text NOT NULL,
			name       text NOT NULL,
			status     text NOT NULL,
			deleted_at timestamptz
		);
		CREATE TABLE `+membersTable+` (
			tenant_id uuid    NOT NULL,
			user_id   text    NOT NULL,
			active    boolean NOT NULL DEFAULT true,
			PRIMARY KEY (tenant_id, user_id)
		);
		GRANT SELECT, INSERT, UPDATE, DELETE ON `+tenantsTable+`, `+membersTable+` TO PUBLIC;`); err != nil {
		t.Fatal(err)
	}

	// The members table is protected; the tenant table is not, because
	// resolving a tenant is what establishes the scope.
	tx, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := security.Enable(tx, membersTable); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	f := fixture{store: sqlstore.New(app, config(membersOf)), owner: owner}
	for slug, into := range map[string]*string{"sqs-acme": &f.acmeID, "sqs-globex": &f.globexID} {
		if err := owner.QueryRowContext(ctx,
			`INSERT INTO `+tenantsTable+` (slug, name, status) VALUES ($1, $2, 'active')
			 RETURNING id`, slug, slug).Scan(into); err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
	}

	// One member each, written as the owner with FORCE lifted — the same
	// escape hatch a data migration uses.
	if _, err := owner.ExecContext(ctx, `ALTER TABLE `+membersTable+` NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][2]string{{f.acmeID, "ada"}, {f.globexID, "grace"}, {f.globexID, "departed"}} {
		if _, err := owner.ExecContext(ctx,
			`INSERT INTO `+membersTable+` (tenant_id, user_id) VALUES ($1, $2)`, row[0], row[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.ExecContext(ctx,
		`UPDATE `+membersTable+` SET active = false WHERE user_id = 'departed'`); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `ALTER TABLE `+membersTable+` FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLookupBySlugAndByID(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	bySlug, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "sqs-acme"})
	if err != nil {
		t.Fatalf("lookup by slug: %v", err)
	}
	if bySlug.ID != f.acmeID || bySlug.Slug != "sqs-acme" || bySlug.Status != tenancy.StatusActive {
		t.Fatalf("lookup by slug gave %+v", bySlug)
	}

	byID, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindID, Value: f.acmeID})
	if err != nil {
		t.Fatalf("lookup by id: %v", err)
	}
	if byID != bySlug {
		t.Errorf("by id gave %+v, by slug %+v", byID, bySlug)
	}

	// Case-insensitive, matching the partial unique index a tenant table
	// should carry on lower(slug).
	upper, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "SQS-ACME"})
	if err != nil || upper.ID != f.acmeID {
		t.Errorf("an uppercase slug gave %+v, %v", upper, err)
	}
}

func TestLookupOfSomethingAbsent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	for name, id := range map[string]tenancy.Identifier{
		"an unknown slug": {Kind: tenancy.KindSlug, Value: "nobody"},
		"an unknown uuid": {Kind: tenancy.KindID, Value: "00000000-0000-4000-8000-000000000000"},
		"no identifier":   {},
	} {
		if _, err := f.store.Lookup(ctx, id); !errors.Is(err, tenancy.ErrNoTenant) {
			t.Errorf("%s gave %v, want ErrNoTenant", name, err)
		}
	}
}

// A soft-deleted tenant has released its slug and must not resolve.
func TestLookupIgnoresASoftDeletedTenant(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	if _, err := f.owner.ExecContext(ctx,
		`UPDATE `+tenantsTable+` SET deleted_at = now() WHERE id = $1`, f.globexID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "sqs-globex"}); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("a soft-deleted tenant resolved: %v", err)
	}
}

// The claim this package exists to make: the membership query carries no
// tenant predicate, and still cannot see another tenant's members.
func TestMembershipIsScopedByThisPackage(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	ada := principal{kind: "user", key: "ada"}
	grace := principal{kind: "user", key: "grace"}

	for name, tc := range map[string]struct {
		tenant    string
		principal tenancy.Principal
		want      bool
	}{
		"a member of acme, in acme":     {f.acmeID, ada, true},
		"a member of globex, in globex": {f.globexID, grace, true},
		"a member of globex, in acme":   {f.acmeID, grace, false},
		"a member of acme, in globex":   {f.globexID, ada, false},
	} {
		t.Run(name, func(t *testing.T) {
			member, err := f.store.IsMember(ctx, tc.tenant, tc.principal)
			if err != nil {
				t.Fatalf("IsMember: %v", err)
			}
			if member != tc.want {
				t.Errorf("IsMember = %v, want %v", member, tc.want)
			}
		})
	}
}

func TestADeactivatedMemberIsNotAMember(t *testing.T) {
	f := setup(t)
	member, err := f.store.IsMember(context.Background(), f.globexID, principal{kind: "user", key: "departed"})
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Error("a deactivated row was counted as a membership")
	}
}

func TestNoPrincipalIsNoMember(t *testing.T) {
	f := setup(t)
	member, err := f.store.IsMember(context.Background(), f.acmeID, nil)
	if err != nil {
		t.Fatalf("a nil principal should not be an error: %v", err)
	}
	if member {
		t.Error("nobody was reported as a member")
	}
}

// A store with no membership query reports that, rather than answering no.
//
// "Nobody is a member of anything" is a sign-in that always fails and reads
// as a permissions bug; the missing configuration should say so.
func TestAStoreWithNoMembershipQuerySaysSo(t *testing.T) {
	f := setup(t)
	bare := sqlstore.New(f.owner, config(nil))

	_, err := bare.IsMember(context.Background(), f.acmeID, principal{kind: "user", key: "ada"})
	if !errors.Is(err, sqlstore.ErrNoMembershipQuery) {
		t.Fatalf("IsMember with no query gave %v, want ErrNoMembershipQuery", err)
	}
}
