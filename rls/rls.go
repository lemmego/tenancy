// Package rls emits and verifies PostgreSQL row-level security for
// tenant-scoped tables.
//
// This is the layer that makes the isolation guarantee. The ORM's tenant
// predicate (orm v0.3.0) gives a good error message and covers the queries it
// builds; it cannot reach hand-written SQL, a reporting tool, or a psql
// session. A policy here applies to every statement the database executes,
// whoever wrote it.
//
// # The part that silently does nothing
//
// A PostgreSQL superuser, and any role with BYPASSRLS, ignores row-level
// security entirely — and FORCE ROW LEVEL SECURITY does not change that.
// FORCE only subjects the table's OWNER to its policies.
//
// So an application that connects as a superuser has no row-level security,
// every policy is decoration, and every test asserting isolation passes while
// proving nothing. On a developer's machine, where the Postgres role is
// usually a superuser, that is the default outcome. AssertNotPrivileged and
// SelfTest exist to turn that silence into a startup error.
package rls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultSetting and DefaultColumn are what an application gets if it says
// nothing.
//
// The setting must be a two-part name — PostgreSQL requires a prefix for a
// custom setting — and an application should namespace it to itself rather
// than take this default, so that two libraries reading "app.tenant_id" in
// one database cannot mean different things by it.
const (
	DefaultSetting = "app.tenant_id"
	DefaultColumn  = "tenant_id"
)

// Config is the two names this package needs, plus the tables it must not
// police.
//
// Parameterised rather than fixed because the column is part of an
// application's schema and the setting is part of its namespace, and a
// framework that hardcoded either would be telling every consumer to rename
// its tables. The zero value is usable: see WithDefaults.
type Config struct {
	// Setting is the transaction-local setting a policy reads.
	Setting string

	// Column is the tenant column every scoped table carries.
	//
	// It has to agree with the `orm:"tenantKey"` field on the models, and
	// that tag is compile-time — so an application whose column is not
	// DefaultColumn declares its own four-line embed instead of using
	// tenancy.Scoped, and sets this to match.
	Column string

	// Unscoped names tables that carry Column and deliberately have no
	// policy, with the reason for each.
	//
	// # Why an exemption list exists at all
	//
	// Conformance exists because the realistic failure is a table gaining a
	// tenant column, no policy, and nobody noticing. An exemption therefore
	// has to be a deliberate, reviewed, written-down act rather than a
	// silent omission — which is what this map is.
	//
	// The test to apply before adding an entry is not "does scoping it break
	// something". It is: is this table read BEFORE a tenant is known, by a
	// caller who could not possibly have named one yet? The tenant registry
	// itself qualifies, because the statement that establishes the scope
	// cannot require a scope. A table read after resolution has no business
	// here, however convenient the exemption would be — and the convenient
	// exemption is how a tenant table ends up unprotected.
	Unscoped map[string]string
}

// WithDefaults fills in whatever the caller left blank.
func (c Config) WithDefaults() Config {
	if c.Setting == "" {
		c.Setting = DefaultSetting
	}
	if c.Column == "" {
		c.Column = DefaultColumn
	}
	return c
}

var (
	// ErrPrivileged means the connected role bypasses row-level security, so
	// none of the policies below apply to it.
	ErrPrivileged = errors.New("rls: the application role bypasses row-level security")

	// ErrNotIsolated means the self-test's scoping did not behave as
	// transaction-local, which is what pooling in statement mode looks like.
	ErrNotIsolated = errors.New("rls: the tenant setting is not transaction-local")

	// ErrBadIdentifier means a table name was not usable in DDL.
	ErrBadIdentifier = errors.New("rls: unusable identifier")
)

// identifier is deliberately strict. Table names here come from Go source,
// not from input, but this is DDL built by string concatenation and the cost
// of being sure is one regexp.
var identifier = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

func quote(table string) (string, error) {
	if !identifier.MatchString(table) {
		return "", fmt.Errorf("%w: %q", ErrBadIdentifier, table)
	}
	return `"` + table + `"`, nil
}

// PolicyName is the policy a table carries. One per table, named from the
// table, so the shape is uniform and a checker can compare it as a string
// rather than parsing it.
func PolicyName(table string) string { return table + "_tenant" }

// Predicate is the expression both USING and WITH CHECK evaluate.
//
// Written out here once so that every table's policy is byte-identical modulo
// the table name — which is what lets a conformance check compare
// pg_policies.qual against a literal instead of parsing SQL.
//
// Two details carry the whole fail-closed property:
//
//   - current_setting(..., true) returns NULL rather than erroring when the
//     setting is absent, and nullif maps the empty string to NULL too. A
//     comparison against NULL is NULL, which is not TRUE, so an unscoped
//     statement matches no rows and inserts nothing. The failure mode of
//     forgetting to scope is therefore "no data", not "all data".
//   - a value that is not a uuid fails the cast and errors the statement,
//     which is also closed.
func (c Config) Predicate() string {
	c = c.WithDefaults()
	return c.Column + " = nullif(current_setting('" + c.Setting + "', true), '')::uuid"
}

// Enable turns on row-level security for a table and installs its policy.
//
// Call it as the last statement of the migration that creates the table.
// Migrations take a *sql.Tx and PostgreSQL DDL is transactional, so this
// either all applies or none of it does.
func (c Config) Enable(tx *sql.Tx, table string) error {
	quoted, err := quote(table)
	if err != nil {
		return err
	}
	for _, statement := range c.enableStatements(table, quoted) {
		if _, err := tx.Exec(statement); err != nil {
			return fmt.Errorf("rls: enabling on %s: %w", table, err)
		}
	}
	return nil
}

func (c Config) enableStatements(table, quoted string) []string {
	return []string{
		"ALTER TABLE " + quoted + " ENABLE ROW LEVEL SECURITY",

		// FORCE subjects the table's owner to the policy as well. Without it
		// the role that runs migrations — which owns every table — reads and
		// writes across tenants, and that role is one connection-string
		// mistake away from being the application's.
		"ALTER TABLE " + quoted + " FORCE ROW LEVEL SECURITY",

		// FOR ALL with both clauses, and both are needed.
		//
		// USING governs which rows SELECT, UPDATE and DELETE can see. WITH
		// CHECK governs what INSERT may write AND the post-image of an
		// UPDATE — so without it a row can be MOVED to another tenant by
		// an update that the USING clause happily permits, because it only
		// checked the row's state before the change. That is the quiet hole
		// in most row-level security write-ups.
		"CREATE POLICY " + PolicyName(table) + " ON " + quoted +
			" AS PERMISSIVE FOR ALL TO PUBLIC" +
			" USING (" + c.Predicate() + ")" +
			" WITH CHECK (" + c.Predicate() + ")",
	}
}

// Suspend lifts FORCE so a migration can touch tenant data as the owner.
//
// Pair it with Resume in the same migration. It is DDL and takes an ACCESS
// EXCLUSIVE lock, which is fine inside a migration and unacceptable in a
// request — which is why this takes a *sql.Tx and lives in a package the
// request path has no reason to import.
func Suspend(tx *sql.Tx, table string) error { return force(tx, table, false) }

// Resume restores FORCE.
func Resume(tx *sql.Tx, table string) error { return force(tx, table, true) }

func force(tx *sql.Tx, table string, on bool) error {
	quoted, err := quote(table)
	if err != nil {
		return err
	}
	clause := "NO FORCE"
	if on {
		clause = "FORCE"
	}
	_, err = tx.Exec("ALTER TABLE " + quoted + " " + clause + " ROW LEVEL SECURITY")
	return err
}

// SetLocal tells the database which tenant this transaction is for.
//
// This is the ONLY place in the codebase that writes the setting, and the
// third argument to set_config is true, meaning transaction-local: PostgreSQL
// resets it at COMMIT or ROLLBACK. That is what makes the whole arrangement
// safe under connection pooling — a connection handed back to the pool
// carries no tenant, so the next request cannot inherit one.
//
// A session-level SET, or set_config(..., false), would leak the tenant to
// whoever gets that connection next. It would also appear to work perfectly
// in development, under one connection and one user.
func (c Config) SetLocal(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenantID string) error {
	return c.SetLocalFunc(ctx, exec.ExecContext, tenantID)
}

// SetLocalFunc is SetLocal for a handle whose method is spelled differently.
//
// It exists for orm.Tx, which offers Exec rather than ExecContext and so
// satisfies no interface this package could declare. The alternative was for
// the caller to write the set_config statement itself, which would mean two
// places in the codebase generating it — and the whole value of there being
// one is that `rg set_config` finds every writer, and that none of them can
// quietly pass false for the third argument.
func (c Config) SetLocalFunc(ctx context.Context,
	exec func(context.Context, string, ...any) (sql.Result, error),
	tenantID string) error {
	_, err := exec(ctx, SetLocalStatement, c.WithDefaults().Setting, tenantID)
	return err
}

// SetLocalStatement is the statement both writers emit.
//
// There are two, and that is deliberate rather than an oversight: this
// package speaks database/sql, for migrations and fixtures that have no ORM,
// while the request path goes through orm.SetTenantSetting, which asks the
// dialect. A test asserts the two produce the same SQL, so the one place they
// could drift apart is guarded.
const SetLocalStatement = "SELECT set_config($1, $2, true)"

// AssertNotPrivileged refuses to continue when the connected role bypasses
// row-level security.
//
// Call it at boot, in every environment. A developer's Postgres role is
// usually a superuser, so without this the policies are inert locally and
// every isolation test is vacuous — and the first time anybody finds out is
// in an environment where it matters.
func AssertNotPrivileged(ctx context.Context, db *sql.DB) error {
	var user string
	var super, bypass bool
	err := db.QueryRowContext(ctx, `
		SELECT current_user, rolsuper, rolbypassrls
		  FROM pg_roles WHERE rolname = current_user`).Scan(&user, &super, &bypass)
	if err != nil {
		return fmt.Errorf("rls: checking the connected role: %w", err)
	}
	if super || bypass {
		return fmt.Errorf(
			"%w: connected as %q (rolsuper=%t, rolbypassrls=%t). Every policy is "+
				"inert for this role and every isolation test would pass while "+
				"proving nothing. Connect as a dedicated role that is neither.",
			ErrPrivileged, user, super, bypass)
	}
	return nil
}

// SelfTest proves, against the live database and its pooler, that the
// tenant setting behaves as transaction-local.
//
// Run it at boot. It converts the one piece of infrastructure that can
// silently destroy the design — a connection pooler in statement mode, where
// a transaction cannot span statements — from an undetectable
// misconfiguration into a startup failure.
func (c Config) SelfTest(ctx context.Context, db *sql.DB) error {
	cfg := c.WithDefaults()
	const sentinel = "00000000-0000-0000-0000-00000000dead"

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("rls: self-test could not begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := c.SetLocal(ctx, tx, sentinel); err != nil {
		return fmt.Errorf("rls: self-test could not scope: %w", err)
	}

	// Two statements after the set, to prove the setting survives within the
	// transaction rather than only on the statement that set it.
	for i := range 2 {
		var got string
		if err := tx.QueryRowContext(ctx,
			"SELECT coalesce(current_setting($1, true), '')", cfg.Setting).Scan(&got); err != nil {
			return fmt.Errorf("rls: self-test read %d: %w", i, err)
		}
		if got != sentinel {
			return fmt.Errorf(
				"%w: statement %d in the transaction saw %q, want the value just set. "+
					"A pooler in statement mode behaves exactly like this, and with it "+
					"there is no row-level security at all.", ErrNotIsolated, i, got)
		}
	}

	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		return err
	}

	// And a fresh connection must see nothing. If it does, the setting was
	// made session-wide and leaks across requests.
	var leaked string
	if err := db.QueryRowContext(ctx,
		"SELECT coalesce(current_setting($1, true), '')", cfg.Setting).Scan(&leaked); err != nil {
		return fmt.Errorf("rls: self-test leak check: %w", err)
	}
	if leaked != "" {
		return fmt.Errorf(
			"%w: the setting survived the transaction as %q, so it is session-level "+
				"and the next request on this connection would inherit it",
			ErrNotIsolated, leaked)
	}
	return nil
}

// Conformance reports tenant-scoped tables whose protection is not what this
// package installs.
//
// The realistic failure is not a broken policy; it is a table added with a
// tenant_id column, no policy and nobody noticing, at which point that
// table has no isolation and nothing fails. Run this in CI.
func (c Config) Conformance(ctx context.Context, db *sql.DB) ([]Finding, error) {
	cfg := c.WithDefaults()
	rows, err := db.QueryContext(ctx, `
		SELECT c.relname,
		       c.relrowsecurity,
		       c.relforcerowsecurity,
		       coalesce((SELECT count(*) FROM pg_policies p
		                  WHERE p.schemaname = n.nspname AND p.tablename = c.relname), 0),
		       coalesce((SELECT string_agg(p.qual, '|') FROM pg_policies p
		                  WHERE p.schemaname = n.nspname AND p.tablename = c.relname), ''),
		       coalesce((SELECT string_agg(coalesce(p.with_check, ''), '|') FROM pg_policies p
		                  WHERE p.schemaname = n.nspname AND p.tablename = c.relname), '')
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind = 'r'
		   AND n.nspname = 'public'
		   AND EXISTS (SELECT 1 FROM pg_attribute a
		                WHERE a.attrelid = c.oid AND a.attname = $1 AND a.attnum > 0 AND NOT a.attisdropped)
		 ORDER BY c.relname`, cfg.Column)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	unscoped := cfg.Unscoped

	var findings []Finding
	for rows.Next() {
		var f Finding
		var qual, withCheck string
		if err := rows.Scan(&f.Table, &f.Enabled, &f.Forced, &f.Policies, &qual, &withCheck); err != nil {
			return nil, err
		}
		if _, declared := unscoped[f.Table]; declared {
			// Declared registry tables are skipped rather than silently
			// passed over: the exemption is a line of Go with a reason
			// attached, which is what keeps it reviewable.
			continue
		}
		switch {
		case !f.Enabled:
			f.Problem = "has a " + cfg.Column + " column but row-level security is not enabled"
		case !f.Forced:
			f.Problem = "row-level security is enabled but not FORCEd, so the table owner bypasses it"
		case f.Policies != 1:
			f.Problem = fmt.Sprintf("has %d policies; expected exactly one", f.Policies)
		case withCheck == "":
			f.Problem = "its policy has no WITH CHECK, so a row can be moved to another tenant"
		}
		if f.Problem != "" {
			findings = append(findings, f)
		}
	}
	return findings, rows.Err()
}

// UnscopedConformance reports a declared registry table that has acquired a
// policy after all.
//
// The inverse mistake, and worth catching because its symptom is baffling:
// an exempt table with a policy answers nothing to everybody — the console
// would list no tenants and resolution would 404 every host — while the
// table looks correctly protected to anybody auditing it.
func (c Config) UnscopedConformance(ctx context.Context, db *sql.DB) ([]Finding, error) {
	var findings []Finding
	cfg := c.WithDefaults()
	for table, reason := range cfg.Unscoped {
		var enabled bool
		var policies int
		err := db.QueryRowContext(ctx, `
			SELECT c.relrowsecurity,
			       coalesce((SELECT count(*) FROM pg_policies p
			                  WHERE p.schemaname = n.nspname AND p.tablename = c.relname), 0)
			  FROM pg_class c
			  JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE c.relkind = 'r' AND n.nspname = 'public' AND c.relname = $1`, table).
			Scan(&enabled, &policies)
		if errors.Is(err, sql.ErrNoRows) {
			// Not a finding. A module whose migrations have not run yet, or
			// a build that does not include this table, is not a failure of
			// isolation.
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("rls: checking the registry table %s: %w", table, err)
		}
		if enabled || policies > 0 {
			findings = append(findings, Finding{
				Table:    table,
				Enabled:  enabled,
				Policies: policies,
				Problem: "is declared unscoped (" + reason + ") but has row-level " +
					"security, so it answers nothing to everybody",
			})
		}
	}
	return findings, nil
}

// Finding is one table whose protection is wrong.
type Finding struct {
	Table    string
	Enabled  bool
	Forced   bool
	Policies int
	Problem  string
}

func (f Finding) String() string { return f.Table + ": " + f.Problem }

// FindingsError turns findings into one error for a CI gate.
func FindingsError(findings []Finding) error {
	if len(findings) == 0 {
		return nil
	}
	lines := make([]string, len(findings))
	for i, f := range findings {
		lines[i] = "  " + f.String()
	}
	return fmt.Errorf("rls: %d table(s) are not isolated:\n%s", len(findings), strings.Join(lines, "\n"))
}
