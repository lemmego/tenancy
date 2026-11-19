package rls_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/lib/pq"

	"github.com/lemmego/tenancy/rls"
)

// These tests need a real PostgreSQL, because row-level security cannot be
// faked and the whole point is to prove the database enforces it.
//
//	TENANCY_OWNER_DSN  — a role that owns the tables and runs migrations
//	TENANCY_APP_DSN    — the role the application connects as
//	TENANCY_SUPER_DSN  — optional: a superuser, used to prove the
//	                         vacuity trap is real rather than theoretical
//
// They skip without them, which is a real hole: a skipped test and a passing
// one are identical in the exit code. CI must set the DSNs and assert that
// none of these skipped.
const (
	alpha = "11111111-1111-1111-1111-111111111111"
	beta  = "22222222-2222-2222-2222-222222222222"
)

// testConfig is the configuration this suite protects its fixtures with.
//
// A deliberately non-default setting name, so a test that accidentally read
// the package default would see nothing rather than quietly pass.
func testConfig() rls.Config {
	return rls.Config{
		Setting: "tenancy_test.tenant_id",
		Column:  "tenant_id",
		Unscoped: map[string]string{
			"tenants": "the tenant table itself: a row in it cannot be scoped " +
				"to the tenant it defines",
		},
	}
}

func dsn(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Skipf("%s is not set, so the database half of the isolation guarantee is unverified", name)
	}
	return value
}

func open(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn(t, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return db
}

// setup creates a tenant-scoped table as the owner, protects it, and seeds
// one row per tenant. Seeding is done as the OWNER with FORCE suspended,
// which is the same escape hatch a data migration uses.
func setup(t *testing.T, table string) {
	t.Helper()
	owner := open(t, "TENANCY_OWNER_DSN")
	ctx := context.Background()

	_, _ = owner.ExecContext(ctx, `DROP TABLE IF EXISTS `+table)

	tx, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		CREATE TABLE `+table+` (
			id            bigserial PRIMARY KEY,
			tenant_id  uuid NOT NULL,
			title         text NOT NULL,
			UNIQUE (tenant_id, id)
		)`); err != nil {
		t.Fatal(err)
	}
	if err := testConfig().Enable(tx, table); err != nil {
		t.Fatal(err)
	}
	// Seed as the owner, with FORCE lifted, exactly as a data migration must.
	if err := rls.Suspend(tx, table); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO `+table+` (tenant_id, title) VALUES ($1,'alpha row'),($2,'beta row')`,
		alpha, beta); err != nil {
		t.Fatal(err)
	}
	if err := rls.Resume(tx, table); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DROP TABLE IF EXISTS ` + table) })
}

// countAs reads the table through db, scoped to tenant, and returns how
// many rows it could see.
func countAs(t *testing.T, db *sql.DB, table, tenant string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()

	if tenant != "" {
		if err := testConfig().SetLocal(ctx, tx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheDatabaseRefusesACrossTenantRead(t *testing.T) {
	setup(t, "rls_docs")
	app := open(t, "TENANCY_APP_DSN")

	if got := countAs(t, app, "rls_docs", alpha); got != 1 {
		t.Fatalf("scoped to alpha the app saw %d rows, want exactly its own 1", got)
	}
	if got := countAs(t, app, "rls_docs", beta); got != 1 {
		t.Fatalf("scoped to beta the app saw %d rows, want exactly its own 1", got)
	}
}

// Forgetting to scope must yield nothing, not everything. This is the
// fail-closed property, and it is the reason the predicate is written with
// current_setting(..., true) and nullif rather than a plain comparison.
func TestAnUnscopedReadSeesNothing(t *testing.T) {
	setup(t, "rls_unscoped")
	app := open(t, "TENANCY_APP_DSN")

	if got := countAs(t, app, "rls_unscoped", ""); got != 0 {
		t.Fatalf("an unscoped read saw %d rows, want 0 — the policy is failing OPEN", got)
	}
}

// WITH CHECK, not just USING. Without it a row can be moved to another
// tenant by an UPDATE that USING permits, because USING only inspects the
// row as it was before the change.
func TestARowCannotBeMovedToAnotherTenant(t *testing.T) {
	setup(t, "rls_move")
	app := open(t, "TENANCY_APP_DSN")
	ctx := context.Background()

	tx, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := testConfig().SetLocal(ctx, tx, alpha); err != nil {
		t.Fatal(err)
	}

	_, err = tx.ExecContext(ctx, `UPDATE rls_move SET tenant_id = $1`, beta)
	if err == nil {
		t.Fatal("the app moved its own row into another tenant; the policy has no WITH CHECK")
	}
}

// An insert naming another tenant is refused by WITH CHECK.
func TestAnInsertIntoAnotherTenantIsRefused(t *testing.T) {
	setup(t, "rls_insert")
	app := open(t, "TENANCY_APP_DSN")
	ctx := context.Background()

	tx, err := app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := testConfig().SetLocal(ctx, tx, alpha); err != nil {
		t.Fatal(err)
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO rls_insert (tenant_id, title) VALUES ($1,'planted')`, beta); err == nil {
		t.Fatal("the app inserted a row into another tenant")
	}
}

// The vacuity proof. The same read that returns one row for the application
// role returns everything for a superuser — so a deployment that connects as
// one has no row-level security, and every test above would pass while
// proving nothing.
func TestASuperuserBypassesEverythingWhichIsWhyTheRoleMatters(t *testing.T) {
	setup(t, "rls_bypass")
	super := open(t, "TENANCY_SUPER_DSN")

	got := countAs(t, super, "rls_bypass", alpha)
	if got != 2 {
		t.Fatalf("expected a superuser to see both rows despite the policy, saw %d — "+
			"if this is 1, PostgreSQL's bypass behaviour has changed and "+
			"AssertNotPrivileged may no longer be necessary", got)
	}
}

func TestAssertNotPrivileged(t *testing.T) {
	ctx := context.Background()

	t.Run("passes for the application role", func(t *testing.T) {
		if err := rls.AssertNotPrivileged(ctx, open(t, "TENANCY_APP_DSN")); err != nil {
			t.Fatalf("the application role should be unprivileged: %v", err)
		}
	})

	t.Run("refuses a superuser", func(t *testing.T) {
		err := rls.AssertNotPrivileged(ctx, open(t, "TENANCY_SUPER_DSN"))
		if !errors.Is(err, rls.ErrPrivileged) {
			t.Fatalf("want ErrPrivileged, got %v", err)
		}
	})
}

// Proves the setting is transaction-local against this database and whatever
// sits in front of it.
func TestSelfTest(t *testing.T) {
	if err := testConfig().SelfTest(context.Background(), open(t, "TENANCY_APP_DSN")); err != nil {
		t.Fatalf("self-test failed: %v", err)
	}
}

// The realistic failure is not a broken policy; it is a table added with a
// tenant_id column and no policy, which nothing notices.
func TestConformanceCatchesAnUnprotectedTable(t *testing.T) {
	owner := open(t, "TENANCY_OWNER_DSN")
	ctx := context.Background()

	_, _ = owner.ExecContext(ctx, `DROP TABLE IF EXISTS rls_forgotten`)
	if _, err := owner.ExecContext(ctx, `
		CREATE TABLE rls_forgotten (
			id bigserial PRIMARY KEY, tenant_id uuid NOT NULL, title text)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DROP TABLE IF EXISTS rls_forgotten`) })

	findings, err := testConfig().Conformance(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range findings {
		if f.Table == "rls_forgotten" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a table with a tenant_id column and no policy was not reported: %v", findings)
	}
	if err := rls.FindingsError(findings); err == nil {
		t.Fatal("FindingsError should report a non-empty finding set")
	}
}

// A declared exemption that has quietly acquired a policy is reported.
//
// The inverse mistake, and worth catching because its symptom is baffling
// rather than loud: an exempt table with a policy answers nothing to
// everybody — the registry lookup that establishes the scope cannot run —
// while the table looks correctly protected to anybody auditing it.
//
// Against a fixture, because the version this replaces declared a table the
// database did not have, and UnscopedConformance skips what is absent by
// design. It passed without examining anything.
func TestADeclaredExemptionThatGainedAPolicyIsReported(t *testing.T) {
	owner := open(t, "TENANCY_OWNER_DSN")
	ctx := context.Background()

	const table = "rls_registry"
	_, _ = owner.ExecContext(ctx, `DROP TABLE IF EXISTS `+table)
	if _, err := owner.ExecContext(ctx, `
		CREATE TABLE `+table+` (id bigserial PRIMARY KEY, tenant_id uuid NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = owner.Exec(`DROP TABLE IF EXISTS ` + table) })

	cfg := testConfig()
	cfg.Unscoped = map[string]string{
		table: "declared by this test as the registry, read before a tenant is known",
	}

	// Exempt and unprotected: nothing to report.
	findings, err := cfg.UnscopedConformance(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := rls.FindingsError(findings); err != nil {
		t.Fatalf("an exempt table with no policy was reported:\n%v", err)
	}

	// Now protect it, which is the mistake.
	tx, err := owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Enable(tx, table); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	findings, err = cfg.UnscopedConformance(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	if rls.FindingsError(findings) == nil {
		t.Fatal("a table declared unscoped was given a policy and nothing reported it")
	}
}

// A declared exemption exempts, and an undeclared table does not.
//
// The old version of this test asserted that every entry in a hardcoded list
// carried a long enough reason. That list belongs to the application now, so
// what is testable here is the behaviour: Conformance skips what the caller
// declared and reports what it did not.
func TestAnExemptionExemptsAndNothingElseDoes(t *testing.T) {
	owner := open(t, "TENANCY_OWNER_DSN")
	ctx := context.Background()

	for _, table := range []string{"rls_exempt", "rls_unprotected"} {
		_, _ = owner.ExecContext(ctx, `DROP TABLE IF EXISTS `+table)
		if _, err := owner.ExecContext(ctx, `
			CREATE TABLE `+table+` (
				id bigserial PRIMARY KEY, tenant_id uuid NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = owner.Exec(`DROP TABLE IF EXISTS ` + table) })
	}

	cfg := testConfig()
	cfg.Unscoped = map[string]string{
		"rls_exempt": "declared by this test as read before a tenant is known",
	}

	findings, err := cfg.Conformance(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	reported := map[string]bool{}
	for _, f := range findings {
		reported[f.Table] = true
	}
	if reported["rls_exempt"] {
		t.Error("a declared exemption was reported anyway, so the list does nothing")
	}
	if !reported["rls_unprotected"] {
		t.Error("an undeclared table with a tenant column was not reported, " +
			"so the check would miss the failure it exists for")
	}
}
