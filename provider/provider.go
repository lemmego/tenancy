// Package provider wires tenancy into a lemmego application.
//
// Two middlewares, and the split between them is forced by when things are
// known:
//
//   - Resolve is an HTTPMiddleware. It runs before the router matches a
//     pattern, which it must, because Go's ServeMux matches hosts exactly and
//     cannot express a wildcard subdomain — so a tenant host is not something
//     the route table can describe. It reads the host and the headers and
//     records which tenant the request is ABOUT.
//
//   - Scoped is an app.Handler on a route group. It runs after authentication,
//     which it must, because deciding whether the caller may have that
//     tenant needs to know who the caller is. It authorises, then opens the
//     request's tenant transaction.
//
// Putting both in one middleware is the mistake worth naming: an
// HTTPMiddleware runs for every request including /build/app-abc123.js, and
// opening a Postgres transaction per static asset is not a thing to do. It
// also runs before auth, so it could only ever authorise an anonymous caller.
package provider

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/lemmego/api/app"
	"github.com/lemmego/orm"

	"github.com/lemmego/tenancy"
	"github.com/lemmego/tenancy/hostname"
	"github.com/lemmego/tenancy/rls"
)

type contextKey int

const (
	keyIdentification contextKey = iota
	keySelected
	keyBinding
	keyTx
)

// Provider installs tenant resolution.
type Provider struct {
	// Config is the deployment's domain layout and header names. A zero
	// Hostnames.AppDomain is refused: resolving every host to the marketing
	// surface because nobody configured a domain is not a sensible default.
	Config tenancy.Config

	// RLS is the row-level security configuration — the setting a policy
	// reads and the column every scoped table carries — for the SetLocal
	// helper below and for an application that wants one place to keep it.
	//
	// Optional. Nothing on the request path reads it: binding the tenant to
	// the query is the ORM's job and happens on every database. This is
	// here for the extension.
	RLS rls.Config

	// Registry resolves identifiers and memberships.
	Registry tenancy.Registry

	// DB is the handle tenant transactions are opened on.
	DB *orm.DB

	// Principal returns who is making the request, or false when nobody is
	// authenticated. Supplied by the application, because this package must
	// not learn what a session is.
	Principal func(app.Context) (tenancy.Principal, bool)

	// SkipPrefixes are paths that never need a tenant: built assets,
	// health checks. Resolution is cheap but not free, and a transaction per
	// static file is neither.
	SkipPrefixes []string

	// RequireEnforcement refuses to boot on a database that cannot bind a
	// tenant to a transaction — which is to say, one where row-level
	// security would have nothing to read.
	//
	// Off by default, because the core of this package does not need it: an
	// application can resolve and bind tenants on any database the ORM
	// supports. Set it when your threat model wants two independent layers
	// and getting one silently would be the failure.
	RequireEnforcement bool
}

var _ app.Provider = (*Provider)(nil)

func (p *Provider) Provide(a app.App) error {
	if p.Config.Hostnames.AppDomain == "" {
		return errors.New("tenancy: no APP_DOMAIN configured; every host would resolve to the marketing surface")
	}
	if p.Registry == nil {
		return errors.New("tenancy: no Registry configured")
	}
	if p.DB == nil {
		return errors.New("tenancy: no DB configured")
	}
	if p.Config.Hostnames.Reserved == nil {
		p.Config.Hostnames.Reserved = hostname.DefaultReserved()
	}
	p.Config = p.Config.WithDefaults()
	p.RLS = p.RLS.WithDefaults()

	// Enforcement is an extension, so it is asked for rather than assumed.
	//
	// The core of this package is resolution and binding: read which tenant
	// a request is about, authorise it, and bind it to the query. That works
	// on every database the ORM supports. Row-level security is an
	// additional layer that PostgreSQL happens to offer; a database without
	// it is not a misconfiguration, it is a database without it.
	//
	// An application that genuinely requires both layers says so, and then
	// this refuses a database that cannot provide the second. That is the
	// right polarity: the default boots everywhere, and the stricter
	// promise is a line somebody wrote.
	if p.RequireEnforcement {
		if _, ok := orm.TenantEnterStatement(p.DB.Dialect()); !ok {
			return fmt.Errorf(
				"tenancy: RequireEnforcement is set and %s cannot bind a tenant to a "+
					"transaction, so row-level security would have no value to read "+
					"and the ORM's predicate would be the only isolation",
				p.DB.Dialect().Name())
		}
	}
	if p.SkipPrefixes == nil {
		p.SkipPrefixes = []string{"/build/", "/static/", "/storage/", "/favicon.ico", "/health", "/livez", "/readyz"}
	}

	// Registered from a provider, which lands this OUTSIDE the middlewares
	// the application installs itself, because providers run before them.
	// That is what puts tenant resolution ahead of the Inertia middleware
	// rather than inside it.
	a.Router().Use(p.resolve())

	// Refuse to serve with a session cookie that is not host-only.
	//
	// One cookie on .example.com would be sent to every tenant
	// subdomain, so acme's session would travel to globex and the
	// per-subdomain isolation this whole design assumes would be gone — in
	// one configuration value, silently, with every test still passing.
	if domain := a.Config().Get("session.domain", ""); domain != "" {
		return fmt.Errorf(
			"tenancy: session.domain is %q and must be empty: a cookie scoped to a "+
				"parent domain is sent to every tenant subdomain, which ends session "+
				"isolation between tenants", domain)
	}
	return nil
}

// resolve reads the host and headers and records what it found.
func (p *Provider) resolve() app.HTTPMiddleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, prefix := range p.SkipPrefixes {
				if strings.HasPrefix(r.URL.Path, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			identification, err := tenancy.Identify(r, p.Config)
			if err != nil {
				switch {
				case errors.Is(err, hostname.ErrUnknownHost), errors.Is(err, hostname.ErrReserved),
					errors.Is(err, hostname.ErrMalformed):
					// 404, and deliberately not logged at error level.
					// Subdomain scanning is constant background noise, and
					// reporting it buries the errors that matter.
					http.NotFound(w, r)
				case errors.Is(err, tenancy.ErrAmbiguous), errors.Is(err, tenancy.ErrBadIdentifier):
					// This one IS worth hearing about: a client that names
					// two tenants, or contradicts the host it reached, is
					// either broken or probing.
					slog.WarnContext(r.Context(), "tenancy: refused a tenant identifier",
						"error", err, "host", r.Host, "path", r.URL.Path)
					http.Error(w, "bad request", http.StatusBadRequest)
				default:
					http.NotFound(w, r)
				}
				return
			}

			ctx := context.WithValue(r.Context(), keyIdentification, identification)

			// Resolve the host to a tenant here, before authentication.
			//
			// Not an optimisation. The users table is scoped to a tenant,
			// so looking a user up with no tenant bound finds nobody —
			// and authentication runs before Scoped, because Scoped needs
			// the user it would produce. Selecting the tenant from the
			// host breaks that circle: the host is not a claim about
			// identity, so resolving it needs no principal.
			//
			// Only for a host. A header-named tenant stays unresolved
			// until Scoped, where a non-member and a nonexistent tenant
			// answer identically — resolving it here would answer 404 for
			// one and something else for the other, which is the
			// enumeration oracle this design exists to avoid.
			if identification.Tenant.Source == tenancy.SourceHost {
				tenant, err := tenancy.Select(ctx, p.Registry, identification)
				switch {
				case err == nil:
					ctx = context.WithValue(ctx, keySelected, tenant)
				case errors.Is(err, tenancy.ErrNoTenant):
					// An unknown subdomain, which is what it genuinely is.
					http.NotFound(w, r)
					return
				default:
					// A registry failure is NOT a 404. A database that is
					// down must not look like a tenant that never existed
					// — that is how an outage gets diagnosed as a DNS
					// problem for two hours.
					slog.ErrorContext(ctx, "tenancy: could not resolve a tenant",
						"error", err, "host", r.Host)
					http.Error(w, "service unavailable", http.StatusServiceUnavailable)
					return
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Scoped authorises the tenant and opens the request's tenant transaction.
//
// Put it on every route group that touches tenant data, after authentication.
// Everything downstream — the rest of the chain, the handler, the renderer —
// runs inside one transaction, which is what lets the database enforce the
// same tenant the ORM does.
func (p *Provider) Scoped(c app.Context) error {
	identification, ok := Identified(c.RequestContext())
	if !ok {
		// Unreachable if resolve ran, so if it happens the chain is wired
		// wrongly and should say so rather than carry on unscoped.
		return c.InternalServerError(errors.New("tenancy: Scoped ran without Resolve"))
	}

	var principal tenancy.Principal
	if p.Principal != nil {
		if who, authenticated := p.Principal(c); authenticated {
			principal = who
		}
	}

	// Confirm when Resolve already selected, Authorize when it could not.
	// Two lookups of the same tenant per request would be wasteful and,
	// worse, could disagree with each other if the row changed in between.
	var binding tenancy.Binding
	var err error
	if selected, ok := Selected(c.RequestContext()); ok {
		binding, err = tenancy.Confirm(c.RequestContext(), p.Registry, selected, identification, principal)
	} else {
		binding, err = tenancy.Authorize(c.RequestContext(), p.Registry, identification, principal)
	}
	if err != nil {
		switch {
		case errors.Is(err, tenancy.ErrNoTenant):
			// The same answer for "no such tenant" and "not yours", so
			// the response cannot be used to enumerate which companies are
			// customers.
			return c.NotFound(err)
		case errors.Is(err, tenancy.ErrNoPrincipal):
			return c.Unauthorized(err)
		case errors.Is(err, tenancy.ErrUnavailable), errors.Is(err, tenancy.ErrAmbiguous):
			return c.BadRequest(err)
		default:
			// A registry failure is NOT a 404. A database that is down must
			// not look like a tenant that does not exist.
			return c.InternalServerError(err)
		}
	}

	readOnly := c.Request().Method == http.MethodGet ||
		c.Request().Method == http.MethodHead ||
		c.Request().Method == http.MethodOptions

	return p.DB.TenantTxOptions(c.RequestContext(), binding.Tenant.ID,
		readOnlyOptions(readOnly), func(tx *orm.Tx) error {
			// SetRequest rather than c.Set, deliberately. c.Set uses the raw
			// string as the context key, and a string key in a context
			// shared by a framework, an application and every module it
			// loads is a collision waiting for the day two of them pick the
			// same word. These keys are unexported and typed, so nothing
			// outside this package can collide with them or forge them.
			request := c.Request()
			ctx := context.WithValue(request.Context(), keyBinding, binding)
			ctx = context.WithValue(ctx, keyTx, tx)
			c.SetRequest(request.WithContext(ctx))
			return c.Next()
		})
}

// readOnlyOptions makes a read-only transaction for a safe method.
//
// Free, and it turns "a GET handler wrote something" into a database error
// rather than a surprise in the data.
func readOnlyOptions(readOnly bool) *sql.TxOptions {
	if !readOnly {
		return nil
	}
	return &sql.TxOptions{ReadOnly: true}
}

// AssertSurface refuses a request that reached a route belonging to another
// surface.
//
// 404 rather than 403: sys.example.com must not confirm that a console
// route exists somewhere.
func AssertSurface(want ...hostname.Surface) app.Handler {
	return func(c app.Context) error {
		got, _ := SurfaceOf(c.RequestContext())
		for _, candidate := range want {
			if got == candidate {
				return c.Next()
			}
		}
		return c.NotFound(fmt.Errorf("tenancy: %s is not served on the %s surface",
			c.Request().URL.Path, got))
	}
}

// Identified returns what Resolve read from the request.
func Identified(ctx context.Context) (tenancy.Identification, bool) {
	identification, ok := ctx.Value(keyIdentification).(tenancy.Identification)
	return identification, ok
}

// Selected returns the tenant the host resolved to, set by Resolve.
//
// It is NOT an authorisation. It says which tenant the request is about,
// which is what a user lookup needs in order to find anybody at all —
// Current is the one that means the caller may have it.
func Selected(ctx context.Context) (tenancy.Tenant, bool) {
	tenant, ok := ctx.Value(keySelected).(tenancy.Tenant)
	return tenant, ok
}

// SurfaceOf returns the surface the request arrived on.
func SurfaceOf(ctx context.Context) (hostname.Surface, bool) {
	identification, ok := Identified(ctx)
	return identification.Surface, ok
}

// Current returns the authorised tenant, set only inside Scoped.
func Current(ctx context.Context) (tenancy.Tenant, bool) {
	binding, ok := ctx.Value(keyBinding).(tenancy.Binding)
	return binding.Tenant, ok
}

// Tx returns the request's tenant transaction, set only inside Scoped.
//
// Note for anyone reaching for this from an Inertia shared prop: do not. The
// renderer resolves each prop in its own goroutine and an orm.Tx is owned by
// one, so a prop that queries races every other prop. Read a value the
// middleware already computed instead.
func Tx(ctx context.Context) (*orm.Tx, bool) {
	tx, ok := ctx.Value(keyTx).(*orm.Tx)
	return tx, ok
}

// SetLocal scopes a handle the same way this provider does, for an
// application that opens its own transaction — a fixture, a migration, or a
// path that runs before the request's own transaction exists.
func (p *Provider) SetLocal(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, tenantID string) error {
	return p.RLS.SetLocal(ctx, exec, tenantID)
}
