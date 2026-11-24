# tenancy

Multi-tenancy for a Lemmego application: which tenant a request is about,
whether the caller may have it, and that tenant bound to every query.

```go
import (
    "github.com/lemmego/tenancy"
    "github.com/lemmego/tenancy/provider"
    "github.com/lemmego/tenancy/sqlstore"
)
```

## The core, and the extension

The **core** is two things, and it works on every database the ORM supports:

1. **Resolution** — read which tenant a request is about, from the host or a
   header, and authorise the caller against their membership of it.
2. **Binding** — bind that tenant to the handle, so the ORM adds a predicate
   to every statement it builds and refuses one built from an unbound handle.

Row-level security is an **extension**. PostgreSQL has it; MySQL and SQLite
do not, and that is not a misconfiguration to work around — it is a database
without the feature. Where it exists it is worth having, because then a
cross-tenant read has to get past two independent layers and a test that
removes either one and still passes is a test proving the other works. Where
it does not, you have the core, which is the part that makes a
client-supplied tenant identifier safe in the first place.

Nothing in this package refuses to run on a database without it. The one
place that can is `Provider.RequireEnforcement`, which is **off by default**
and exists for an application whose threat model wants both layers and for
which silently getting one would be the failure.

| | PostgreSQL | MySQL | SQLite |
|---|---|---|---|
| resolution, authorisation, binding | yes | yes | yes |
| row-level security (`tenancy/rls`) | yes | — | — |

`sqlstore` is configured for the vendor — a placeholder spelling, an optional
id cast — and its membership check is scoped only when you give it something
to scope with. There is no `mysqlstore`, deliberately: the store is the
portable half, and the half that is not portable is not a store.

## How a request names a tenant

Two ways, and the difference between them is most of this package.

**The host.** `acme.example.com` names acme. A browser cannot forge this — it
is where the request went, and the session cookie that came with it is scoped
to that exact host.

**A header.** `X-Tenant-Slug: acme`, or `X-Tenant-ID: <uuid>`. For an API
client with no per-tenant host, and for a mobile app that knows which tenant
it signed into. Both names are configurable, because they are part of your
public API: a product whose tenants are "workspaces" will want
`X-Workspace-Slug`, and its clients are already sending it.

```go
cfg := tenancy.Config{
    Hostnames: hostname.Config{AppDomain: "example.com", Reserved: hostname.DefaultReserved()},
    SlugHeader: "X-Workspace-Slug",   // optional; defaults to X-Tenant-Slug
}
identification, err := tenancy.Identify(request, cfg)
```

### A header selects. It does not authorise.

This is the part worth reading twice. A header is client-supplied, so on its
own it says nothing about whether the caller may see that tenant. Taking the
tenant from a header and scoping the query to it — with nothing else — means
any authenticated member of one tenant can read another by typing its id, and
**both** the ORM predicate and the row-level security policy will enforce
that choice perfectly. The isolation machinery is not what protects you here.

So `Identify` answers only "which tenant is this request *about*". The binding
comes from the caller's **membership**:

```go
binding, err := tenancy.Authorize(ctx, registry, identification, principal)
```

A caller who names a tenant they do not belong to gets `ErrNoTenant` — the
same error as a tenant that does not exist, deliberately, because a distinct
"forbidden" would confirm which companies are customers and let anybody
enumerate the tenant list from a sign-in page.

`Select` and `Confirm` are the two halves, for the case that forces them
apart: a user lookup needs a tenant (the users table is scoped), and
authorising needs the user that lookup produces. Resolve the host first,
authorise after, with nothing bound in between.

## Surfaces

`hostname` compares **label depth** against one configured domain, so
`example.localhost` and `example.com` behave identically and there is no
development branch to get wrong.

| Host | Surface |
|---|---|
| `example.com` | `SurfaceMarketing` |
| `sys.example.com` | `SurfacePlatform` |
| `app.example.com` | `SurfaceConsole` |
| `acme.example.com` | `SurfaceTenant`, slug `acme` |

Both conditions in the match are needed, and the second is the one that
matters: a suffix test alone accepts `evil.acme.example.com`, and a naive
prefix-strip then reads the label as `evil.acme` — or, worse, somebody
helpfully takes the first label and serves acme's data to a host acme does not
control. Requiring exactly one more label than the app domain refuses the
whole shape.

`ValidateLabel` decides what may be **registered**, and it does so by
building the host the label would answer on and asking `Resolve` what that
host means. A label is registrable exactly when a host made from it resolves
back to a tenant with that slug. That is the only arrangement in which
creation and routing cannot drift — and the case a hand-written copy of the
rules always misses is a configured surface label: set `ConsoleLabel: "portal"`
and `portal` must become unregistrable, because `Resolve` answers the surface
before it considers a tenant at all.

## The extension: PostgreSQL row-level security

`rls` emits and verifies PostgreSQL row-level security.

```go
security := rls.Config{Setting: "acme.tenant_id", Column: "tenant_id"}

// In the migration that creates a tenant-scoped table, as its last statement:
if err := security.Enable(tx, "invoices"); err != nil { return err }
```

That installs `ENABLE`, `FORCE` and one policy whose text is byte-identical
across tables modulo the name — which is what lets a conformance check
compare it as a string instead of parsing SQL. Three details carry the
guarantee:

- **`FORCE`**, so the table's owner is subject too. Without it the role that
  runs migrations reads and writes across tenants, and that role is one
  connection string away from being the application's.
- **`WITH CHECK` as well as `USING`.** `USING` governs what you can *see*, so
  without `WITH CHECK` a row can be **moved** to another tenant by an
  `UPDATE` the `USING` clause happily permits — it only checked the row's
  state before the change. That is the quiet hole in most RLS write-ups.
- **`current_setting(…, true)` + `nullif`**, so an unset setting yields NULL,
  and `tenant_id = NULL` is never true. It fails closed *by construction*:
  the failure mode of forgetting to scope is "no data", not "all data".

### Telling the database which tenant

The ORM's `WithTenantEnter` hook runs as each tenant transaction opens, and
`orm.SetTenantSetting` asks the dialect for the statement:

```go
db := orm.Open(sqlDB, orm.Postgres(),
    orm.WithTenantEnter(orm.SetTenantSetting(security.Setting)))
```

It is **transaction-local**, so it resets at commit or rollback and cannot
reach the next user of a pooled connection — which is what makes this safe
behind a pooler in transaction mode. A session-level `SET` would leak the
tenant and would look perfect in development, under one connection and one
user.

On MySQL or SQLite there is no equivalent, so there is nothing for a policy
to read — and nothing here objects. The core does not need it. If your
application does, set `Provider.RequireEnforcement` and a database that
cannot bind a tenant to a transaction is refused at boot rather than
discovered at the first request.

### Two checks to run at boot, in every environment

```go
rls.AssertNotPrivileged(ctx, db)   // the role is not a superuser and has no BYPASSRLS
cfg.SelfTest(ctx, db)               // the setting really is transaction-local
```

The first matters because **a superuser bypasses row-level security entirely,
and `FORCE` does not change that** — `FORCE` only subjects the table's owner.
A developer's PostgreSQL role is usually a superuser, so without this check
the policies are inert locally and every isolation test passes while proving
nothing. The second converts the one infrastructure choice that would silently
destroy the design — a pooler in *statement* mode — into a startup error.

### Conformance

The realistic failure is not a broken policy. It is a table that gains a
tenant column, no policy, and nobody notices: tests pass, the page works, and
a customer finds it.

```go
findings, _ := security.Conformance(ctx, db)
if err := rls.FindingsError(findings); err != nil { return err }   // run this in CI
```

`Config.Unscoped` is the exemption list, and it exists so that an exemption is
a deliberate, reviewed, written-down act rather than a silent omission. The
test to apply before adding an entry is **not** "does scoping it break
something". It is: is this table read *before* a tenant is known, by a caller
who could not possibly have named one yet? The tenant registry itself
qualifies — the statement that establishes the scope cannot require a scope.
Anything read after resolution does not, however convenient the exemption
would be.

`UnscopedConformance` catches the inverse, whose symptom is baffling rather
than loud: an exempt table that acquires a policy answers nothing to
everybody, while looking correctly protected to anybody auditing it.

## Models

```go
type Invoice struct {
    tenancy.Scoped          // TenantID string `db:"tenant_id" orm:"column:tenant_id;tenantKey"`
    ID    uint64 `db:"id" orm:"primaryKey;autoIncrement"`
    Total int64  `db:"total_cents"`
}
```

The embed declares the column, the tag and the type in one place, so there is
nothing per-model to get subtly wrong, and `rg tenancy.Scoped` lists every
scoped model — which is what lets a conformance check cross-check the models
against the tables that actually carry a policy.

**If your column is not `tenant_id`, declare your own four-line embed.** A
struct tag is compile-time and cannot be configured, so this is the one thing
`Config.Column` cannot do for you; set `Column` to match whatever you declare.

The ORM detects the `tenantKey` tag and never the field name, deliberately: a
naming convention would mean that renaming a field silently changes whether a
table is isolated.

## The registry

Two questions, and your application answers both:

```go
type Registry interface {
    Lookup(ctx context.Context, id Identifier) (Tenant, error)
    IsMember(ctx context.Context, tenantID string, principal Principal) (bool, error)
}
```

`sqlstore` implements it over any SQL database. `Lookup` is uniform enough to
configure — a table with an id, a slug, a name and a status — but membership
is yours: which table holds it, and what a membership means for each
population of caller, is not something a library can know. So you supply the
query and `sqlstore` supplies the thing that is easy to get wrong:

```go
store := sqlstore.New(db, sqlstore.Config{
    Table: "workspaces",
    Scope: security.SetLocal,   // the extension; omit it and Members filters itself
    Members: func(ctx context.Context, tx *sql.Tx, tenantID string, p tenancy.Principal) (bool, error) {
        // tx is ALREADY scoped to tenantID, so this needs no tenant predicate
        // and cannot see another tenant's rows.
        var exists bool
        err := tx.QueryRowContext(ctx,
            `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1::bigint AND active)`,
            p.PrincipalKey()).Scan(&exists)
        return exists, err
    },
})
```

The membership check opens its own short read-only transaction and scopes it.
The obvious alternative is to run it through a role that bypasses the policy,
and that is the wrong fix: it would put a `BYPASSRLS` connection on the
authentication path of every single request, which is the one place it must
never be.

## Wiring

```go
&provider.Provider{
    Config:   cfg,
    RLS:      security,
    Registry: store,
    DB:       db,
    Principal: func(c app.Context) (tenancy.Principal, bool) { … },
}
```

Two middlewares, and the split is forced by *when things are known*:

- **`resolve`** is an `app.HTTPMiddleware`, installed by `Provide` through
  `Router().Use`, so it runs before the router matches a pattern — which it
  must, because Go's `ServeMux` matches hosts exactly and cannot express a
  wildcard subdomain, so a tenant host is not something the route table can
  describe.
- **`Scoped`** is an `app.Handler` on a route group. It runs *after*
  authentication, which it must, because deciding whether the caller may have
  that tenant needs to know who the caller is. It authorises, then opens the
  request's tenant transaction.

Putting both in one middleware is the mistake worth naming: an
`HTTPMiddleware` runs for every request including `/build/app-abc123.js`, and
opening a transaction per static asset is not a thing to do.

`AssertSurface` guards a route group, answering **404 rather than 403** — so
`sys.example.com` never confirms that a console route exists somewhere.

`Provide` also refuses to start when `session.domain` is set. One cookie on
`.example.com` is sent to every tenant subdomain, so acme's session would
travel to globex and the per-subdomain isolation this whole design assumes
would be gone — in one configuration value, silently, with every test still
passing.

## Reading values back

```go
tenancy.Identified(ctx)  // what resolve read: the surface, and the identifier
provider.Selected(ctx)   // the tenant the host resolved to — NOT an authorisation
provider.Current(ctx)    // the authorised tenant, set only inside Scoped
provider.Tx(ctx)         // the request's tenant transaction
```

`Selected` says which tenant the request is *about*, which is what a user
lookup needs in order to find anybody at all. `Current` is the one that means
the caller may have it.

**Do not reach `Tx` from an Inertia shared prop.** The renderer resolves each
prop in its own goroutine and an `orm.Tx` is owned by one, so a prop that
queries races every other prop. Read a value the middleware already computed.

## What this package does not do

- **It does not know what a user is.** `Principal` is two strings, so this
  package never learns what a password is or whether the caller is a person,
  a device or a machine token.
- **It does not cache.** `Lookup` runs per request. A cache belongs in front
  of your `Registry`, keyed per source — conflating a host-resolved and a
  header-resolved entry means one can poison the other, which is a tenant
  leak rather than a cache bug, and `Binding.Source` is there so you can key
  them apart.
- **It does not filter `Raw` SQL or many-to-many pivot reads.** Neither does
  the ORM, and for the same reason: there is nowhere to inject a predicate
  into hand-written SQL, and a pivot is a bare table with no model and so no
  declared tenant column. Both are row-level security's job, which is why it
  is not optional.

## Verification

```sh
export TENANCY_OWNER_DSN="postgres://owner@127.0.0.1:5432/tenancy_test?sslmode=disable"
export TENANCY_APP_DSN="postgres://app@127.0.0.1:5432/tenancy_test?sslmode=disable"
export TENANCY_SUPER_DSN="postgres://postgres@127.0.0.1:5432/tenancy_test?sslmode=disable"
go test ./... -count=1 -race -v
```

Three roles, because the suite proves the difference between them: `app` is
subject to every policy, `owner` owns the tables and is *still* subject
because `FORCE` says so, and the superuser bypasses them — which is what
`TestASuperuserBypassesEverythingWhichIsWhyTheRoleMatters` exists to
demonstrate. Without the DSNs the database half skips, and the skip message
says what is unverified: a suite that skips and a suite that passes share an
exit code.
