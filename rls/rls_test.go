package rls_test

import (
	"strings"
	"testing"

	"github.com/lemmego/orm"

	"github.com/lemmego/tenancy/rls"
)

// There are two writers of the statement that binds a tenant, and this is
// the test that keeps them one statement.
//
// This package speaks database/sql, for a migration or a fixture that has no
// ORM; the request path goes through orm.SetTenantSetting, which asks the
// dialect. Both are legitimate and neither can be removed — so the one place
// they could drift apart is pinned here. If this fails, one of them changed
// and the other did not, and the half that did not is silently doing
// something else.
func TestTheSetLocalStatementMatchesTheORMs(t *testing.T) {
	fromORM, ok := orm.TenantEnterStatement(orm.Postgres())
	if !ok {
		t.Fatal("the postgres dialect no longer reports a tenant-enter statement")
	}
	if rls.SetLocalStatement != fromORM {
		t.Fatalf("two spellings of one statement:\n  rls: %q\n  orm: %q",
			rls.SetLocalStatement, fromORM)
	}
}

// The predicate fails closed by construction, not by convention.
//
// current_setting(..., true) yields NULL rather than erroring when the
// setting is absent, nullif maps the empty string to NULL too, and a
// comparison against NULL is NULL — which is not TRUE. So an unscoped
// statement matches no rows and inserts nothing: the failure mode of
// forgetting to scope is "no data", not "all data".
//
// Asserted as text because that is where the property lives; the behaviour
// is proven against a real database in rls_integration_test.go.
func TestThePredicateFailsClosed(t *testing.T) {
	predicate := rls.Config{}.Predicate()

	for _, fragment := range []string{"nullif(", "current_setting(", ", true)", "::uuid"} {
		if !strings.Contains(predicate, fragment) {
			t.Errorf("predicate %q is missing %q, without which it does not fail closed", predicate, fragment)
		}
	}
}

// The column and the setting are the two things an application names, and
// both have to reach the policy.
//
// Two configurations differing in exactly those tokens must produce
// predicates differing in exactly those tokens — which is what makes the
// parameterisation real rather than a field nothing reads.
func TestTheColumnAndTheSettingReachThePolicy(t *testing.T) {
	standard := rls.Config{}.Predicate()
	custom := rls.Config{Setting: "acme.workspace", Column: "workspace_id"}.Predicate()

	if standard == custom {
		t.Fatal("two different configurations produced the same predicate")
	}
	if !strings.Contains(custom, "workspace_id =") {
		t.Errorf("the configured column does not lead the predicate: %q", custom)
	}
	if !strings.Contains(custom, "'acme.workspace'") {
		t.Errorf("the configured setting does not reach the predicate: %q", custom)
	}
	// And nothing of the default survives into the custom one, which is what
	// a half-threaded parameter would look like.
	if strings.Contains(custom, rls.DefaultColumn+" =") || strings.Contains(custom, rls.DefaultSetting) {
		t.Errorf("the default leaked into a configured predicate: %q", custom)
	}
}

func TestTheZeroConfigIsUsable(t *testing.T) {
	filled := rls.Config{}.WithDefaults()
	if filled.Setting != rls.DefaultSetting || filled.Column != rls.DefaultColumn {
		t.Fatalf("WithDefaults gave %+v", filled)
	}
	// And a partially-filled one keeps what it was given.
	partial := rls.Config{Column: "tenant"}.WithDefaults()
	if partial.Column != "tenant" || partial.Setting != rls.DefaultSetting {
		t.Errorf("WithDefaults overwrote a value it was given: %+v", partial)
	}
}

// A policy is named from its table, so a conformance check can compare it as
// a string rather than parsing SQL.
func TestAPolicyIsNamedFromItsTable(t *testing.T) {
	if got := rls.PolicyName("invoices"); got != "invoices_tenant" {
		t.Errorf("PolicyName(invoices) = %q", got)
	}
}
