package tenancy

// Scoped is embedded by every model whose rows belong to a tenant.
//
//	type Site struct {
//	    tenancy.Scoped
//	    ID   uint64 `db:"id" orm:"primaryKey;autoIncrement"`
//	    Name string `db:"name"`
//	}
//
// Embedding it does three things at once, which is the reason it exists
// rather than each model declaring the column itself:
//
//   - it declares the column name, the tag and the type in ONE place, so
//     there is nothing per-model to get subtly wrong;
//   - the orm:"tenantKey" tag makes every statement the ORM builds for that
//     model carry an implicit tenant predicate, and makes a query through
//     an unbound handle an error rather than an unfiltered result set;
//   - `rg tenancy.Scoped` lists every tenant-scoped model in the codebase,
//     which is what lets a conformance test cross-check the models against
//     the tables that actually carry a row-level security policy.
//
// The ORM detects the tag and NOT the field name, deliberately: a naming
// convention would mean that renaming a field silently changes whether a
// table is isolated.
//
// A model embedding this must never be written through a handle that is not
// bound to a tenant. Nothing sets TenantID by hand — the ORM fills it
// from the binding on insert, and refuses a value naming a different
// tenant.
type Scoped struct {
	TenantID string `db:"tenant_id" orm:"column:tenant_id;tenantKey"`
}

// Tenant returns the tenant this row belongs to.
func (s Scoped) Tenant() string { return s.TenantID }
