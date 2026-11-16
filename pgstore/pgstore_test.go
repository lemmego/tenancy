package pgstore_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/lemmego/fieldbubble/tenancy"
	"github.com/lemmego/fieldbubble/tenancy/pgstore"
)

// Against the real schema, because the thing being tested is whether a
// membership check works through a row-level security policy — which cannot
// be established without the policy.
//
//	FIELDBUBBLE_OWNER_DSN  creates the fixture
//	FIELDBUBBLE_APP_DSN    what the store uses, unprivileged like production

type principal struct{ kind, key string }

func (p principal) PrincipalKind() string { return p.kind }
func (p principal) PrincipalKey() string  { return p.key }

type fixture struct {
	store            *pgstore.Store
	acmeID, globexID string
	adaInAcme        string
	graceInGlobex    string
}

func setup(t *testing.T) fixture {
	t.Helper()
	ownerDSN, appDSN := os.Getenv("FIELDBUBBLE_OWNER_DSN"), os.Getenv("FIELDBUBBLE_APP_DSN")
	if ownerDSN == "" || appDSN == "" {
		t.Skip("FIELDBUBBLE_OWNER_DSN and FIELDBUBBLE_APP_DSN are unset, so the membership path is unverified")
	}

	owner, err := sql.Open("postgres", ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close() })

	app, err := sql.Open("postgres", appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })

	ctx := context.Background()
	f := fixture{store: pgstore.New(app)}

	// A clean slate for the slugs these tests use, then two workspaces with
	// one member each. Seeded as the owner with FORCE lifted, which is the
	// same escape hatch a data migration uses.
	if _, err := owner.ExecContext(ctx, `
		ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
		DELETE FROM users WHERE email LIKE '%@pgstore.test';
		DELETE FROM workspaces WHERE slug IN ('pgs-acme','pgs-globex','pgs-gone');
		ALTER TABLE users FORCE ROW LEVEL SECURITY;`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = owner.Exec(`
			ALTER TABLE users NO FORCE ROW LEVEL SECURITY;
			DELETE FROM users WHERE email LIKE '%@pgstore.test';
			DELETE FROM workspaces WHERE slug IN ('pgs-acme','pgs-globex','pgs-gone');
			ALTER TABLE users FORCE ROW LEVEL SECURITY;`)
	})

	if err := owner.QueryRowContext(ctx,
		`INSERT INTO workspaces (slug,name,status) VALUES ('pgs-acme','Acme','active') RETURNING id`).
		Scan(&f.acmeID); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx,
		`INSERT INTO workspaces (slug,name,status) VALUES ('pgs-globex','Globex','active') RETURNING id`).
		Scan(&f.globexID); err != nil {
		t.Fatal(err)
	}

	if _, err := owner.ExecContext(ctx, `ALTER TABLE users NO FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx,
		`INSERT INTO users (workspace_id,email,name,password) VALUES ($1,'ada@pgstore.test','Ada','x') RETURNING id`,
		f.acmeID).Scan(&f.adaInAcme); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRowContext(ctx,
		`INSERT INTO users (workspace_id,email,name,password) VALUES ($1,'grace@pgstore.test','Grace','x') RETURNING id`,
		f.globexID).Scan(&f.graceInGlobex); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.ExecContext(ctx, `ALTER TABLE users FORCE ROW LEVEL SECURITY`); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLookupBySlugAndByID(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	bySlug, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "pgs-acme"})
	if err != nil {
		t.Fatal(err)
	}
	if bySlug.ID != f.acmeID || bySlug.Status != tenancy.StatusActive {
		t.Fatalf("by slug = %+v", bySlug)
	}

	byID, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindID, Value: f.acmeID})
	if err != nil {
		t.Fatal(err)
	}
	if byID.Slug != "pgs-acme" {
		t.Fatalf("by id = %+v", byID)
	}

	// Case-insensitive, matching the index the migration creates.
	upper, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "PGS-ACME"})
	if err != nil || upper.ID != f.acmeID {
		t.Fatalf("uppercase lookup: %+v %v", upper, err)
	}
}

func TestLookupOfSomethingAbsent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()

	for name, id := range map[string]tenancy.Identifier{
		"unknown slug": {Kind: tenancy.KindSlug, Value: "pgs-gone"},
		"unknown uuid": {Kind: tenancy.KindID, Value: "99999999-9999-9999-9999-999999999999"},
		"no kind":      {},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.store.Lookup(ctx, id); !errors.Is(err, tenancy.ErrNoWorkspace) {
				t.Fatalf("want ErrNoWorkspace, got %v", err)
			}
		})
	}
}

// A soft-deleted workspace is gone, and its slug is free for somebody else.
func TestLookupIgnoresASoftDeletedWorkspace(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner, _ := sql.Open("postgres", os.Getenv("FIELDBUBBLE_OWNER_DSN"))
	defer owner.Close()

	if _, err := owner.ExecContext(ctx,
		`UPDATE workspaces SET deleted_at = now() WHERE id = $1`, f.acmeID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "pgs-acme"}); !errors.Is(err, tenancy.ErrNoWorkspace) {
		t.Fatalf("a soft-deleted workspace still resolves: %v", err)
	}
}

// The check that makes a client-supplied header safe, against the real policy.
func TestIsMemberOnlyWhereTheCallerHasARow(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ada := principal{kind: "user", key: f.adaInAcme}
	grace := principal{kind: "user", key: f.graceInGlobex}

	cases := []struct {
		name      string
		workspace string
		who       tenancy.Principal
		want      bool
	}{
		{"ada in her own workspace", f.acmeID, ada, true},
		{"ada in somebody else's", f.globexID, ada, false},
		{"grace in her own workspace", f.globexID, grace, true},
		{"grace in somebody else's", f.acmeID, grace, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := f.store.IsMember(ctx, tc.workspace, tc.who)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("IsMember = %v, want %v", got, tc.want)
			}
		})
	}
}

// Deactivating somebody revokes membership immediately, without touching a
// cache — which is the property the design leans on for "remove this person
// and get them out now".
func TestADeactivatedUserIsNotAMember(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	owner, _ := sql.Open("postgres", os.Getenv("FIELDBUBBLE_OWNER_DSN"))
	defer owner.Close()

	// Three separate statements, not one. A parameterised Exec goes over the
	// extended protocol, where PostgreSQL refuses multiple commands in one
	// prepared statement — the same constraint that makes a migration through
	// a transaction pooler fail.
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{sql: `ALTER TABLE users NO FORCE ROW LEVEL SECURITY`},
		{sql: `UPDATE users SET active = false WHERE id = $1`, args: []any{f.adaInAcme}},
		{sql: `ALTER TABLE users FORCE ROW LEVEL SECURITY`},
	} {
		if _, err := owner.ExecContext(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal(err)
		}
	}

	member, err := f.store.IsMember(ctx, f.acmeID, principal{kind: "user", key: f.adaInAcme})
	if err != nil {
		t.Fatal(err)
	}
	if member {
		t.Fatal("a deactivated user is still a member")
	}
}

func TestNoPrincipalIsNoMember(t *testing.T) {
	f := setup(t)
	got, err := f.store.IsMember(context.Background(), f.acmeID, nil)
	if err != nil || got {
		t.Fatalf("IsMember(nil) = %v, %v", got, err)
	}
}

// An unimplemented population is an error, not a quiet false. A quiet false
// would present as a baffling permission problem rather than as the missing
// implementation it is.
func TestAnUnknownPrincipalKindIsAnError(t *testing.T) {
	f := setup(t)
	_, err := f.store.IsMember(context.Background(), f.acmeID, principal{kind: "superuser", key: "7"})
	if err == nil {
		t.Fatal("want an error for a principal kind with no membership rule")
	}
}

// Authorize over the real store: the whole path a header takes.
func TestAuthorizeRefusesAHeaderNamingAnotherWorkspace(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	ada := principal{kind: "user", key: f.adaInAcme}

	mine := tenancy.Identification{Workspace: tenancy.Identifier{
		Kind: tenancy.KindSlug, Value: "pgs-acme", Source: tenancy.SourceHeader}}
	if _, err := tenancy.Authorize(ctx, f.store, mine, ada); err != nil {
		t.Fatalf("ada should reach her own workspace: %v", err)
	}

	theirs := tenancy.Identification{Workspace: tenancy.Identifier{
		Kind: tenancy.KindSlug, Value: "pgs-globex", Source: tenancy.SourceHeader}}
	if _, err := tenancy.Authorize(ctx, f.store, theirs, ada); !errors.Is(err, tenancy.ErrNoWorkspace) {
		t.Fatalf("want ErrNoWorkspace, got %v", err)
	}
}
