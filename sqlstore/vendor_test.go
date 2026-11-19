package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/lemmego/tenancy"
	"github.com/lemmego/tenancy/sqlstore"
)

// The core works on a database with no row-level security, and this is the
// test that says so rather than the README.
//
// Resolving which tenant a request is about, and authorising the caller
// against their membership of it, is the whole core of this package.
// Row-level security is an additional layer PostgreSQL happens to offer. A
// database without it is not a misconfiguration — so the suite that proves
// the core must run somewhere that has none.
//
// SQLite, in memory, with no DSN: this one can never skip, which is the
// point. The PostgreSQL suite beside it needs three roles and skips without
// them, and a skip and a pass share an exit code.
func TestTheCoreWorksWithoutRowLevelSecurity(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	// One connection, so ":memory:" is one database rather than one per
	// pooled connection — each gets its own empty schema otherwise.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE tenants (
			id text PRIMARY KEY, slug text NOT NULL, name text NOT NULL,
			status text NOT NULL, deleted_at text);
		CREATE TABLE members (
			tenant_id text NOT NULL, user_id text NOT NULL,
			PRIMARY KEY (tenant_id, user_id));
		INSERT INTO tenants (id, slug, name, status) VALUES
			('acme-id', 'acme', 'Acme', 'active'),
			('globex-id', 'globex', 'Globex', 'active');
		INSERT INTO members (tenant_id, user_id) VALUES
			('acme-id', 'ada'), ('globex-id', 'grace');`); err != nil {
		t.Fatal(err)
	}

	store := sqlstore.New(db, sqlstore.Config{
		// What portability costs, in full.
		//
		// A caveat this test cannot prove: SQLite accepts $1 as a parameter
		// too, so removing Placeholder leaves this passing — the knob is
		// exercised, not shown to be necessary. It is necessary for MySQL,
		// which accepts only ?, and proving that wants a MySQL service.
		// Said here rather than left implied, because a test that looks
		// like it covers something is worse than one that admits it does
		// not. IDCast and the absent Scope are both load-bearing here, and
		// both were verified by removing them.
		Placeholder: sqlstore.QuestionPlaceholder,
		IDCast:      sqlstore.None,
		// No Scope: there is no row-level security to scope, so the
		// membership query below carries its own predicate. That is the
		// contract, and the test for the other half of it is that the
		// query is handed the tenant id in order to do so.
		Members: func(ctx context.Context, tx *sql.Tx, tenantID string, p tenancy.Principal) (bool, error) {
			var exists bool
			err := tx.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM members WHERE tenant_id = ? AND user_id = ?)`,
				tenantID, p.PrincipalKey()).Scan(&exists)
			return exists, err
		},
	})

	acme, err := store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "acme"})
	if err != nil {
		t.Fatalf("resolving a tenant by slug on SQLite: %v", err)
	}
	if acme.ID != "acme-id" || acme.Status != tenancy.StatusActive {
		t.Fatalf("lookup gave %+v", acme)
	}

	byID, err := store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindID, Value: "acme-id"})
	if err != nil || byID != acme {
		t.Fatalf("lookup by id gave %+v, %v", byID, err)
	}

	if _, err := store.Lookup(ctx, tenancy.Identifier{Kind: tenancy.KindSlug, Value: "nobody"}); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Errorf("an unknown slug gave %v, want ErrNoTenant", err)
	}

	// And authorisation still refuses a non-member, which is the half that
	// matters: a header naming a tenant is only safe because membership
	// decides, and that is true with or without a policy behind it.
	for name, tc := range map[string]struct {
		tenant string
		who    string
		want   bool
	}{
		"a member":     {"acme-id", "ada", true},
		"a non-member": {"acme-id", "grace", false},
	} {
		t.Run(name, func(t *testing.T) {
			member, err := store.IsMember(ctx, tc.tenant, principal{kind: "user", key: tc.who})
			if err != nil {
				t.Fatalf("IsMember: %v", err)
			}
			if member != tc.want {
				t.Errorf("IsMember = %v, want %v", member, tc.want)
			}
		})
	}
}

// Authorize is the part that makes a client-supplied identifier safe, and it
// has no database in it at all — so it holds on every vendor by construction.
func TestAuthorizationRefusesANonMemberOnAnyVendor(t *testing.T) {
	registry := fixedRegistry{
		tenants: map[string]tenancy.Tenant{
			"acme": {ID: "acme-id", Slug: "acme", Status: tenancy.StatusActive},
		},
		members: map[string]string{"acme-id": "ada"},
	}

	ident := tenancy.Identification{
		Surface: 0,
		Tenant:  tenancy.Identifier{Kind: tenancy.KindSlug, Value: "acme", Source: tenancy.SourceHeader},
	}

	if _, err := tenancy.Authorize(context.Background(), registry, ident,
		principal{kind: "user", key: "grace"}); !errors.Is(err, tenancy.ErrNoTenant) {
		t.Fatalf("a non-member was authorised, or refused with the wrong error: %v", err)
	}
	if _, err := tenancy.Authorize(context.Background(), registry, ident,
		principal{kind: "user", key: "ada"}); err != nil {
		t.Fatalf("a member was refused: %v", err)
	}
}

type fixedRegistry struct {
	tenants map[string]tenancy.Tenant
	members map[string]string
}

func (r fixedRegistry) Lookup(_ context.Context, id tenancy.Identifier) (tenancy.Tenant, error) {
	if tenant, ok := r.tenants[id.Value]; ok {
		return tenant, nil
	}
	return tenancy.Tenant{}, tenancy.ErrNoTenant
}

func (r fixedRegistry) IsMember(_ context.Context, tenantID string, p tenancy.Principal) (bool, error) {
	return r.members[tenantID] == p.PrincipalKey(), nil
}
