// Package provider wires tenancy into a lemmego application.
//
// Two middlewares, and the split between them is forced by when things are
// known:
//
//   - Resolve is an HTTPMiddleware. It runs before the router matches a
//     pattern, which it must, because Go's ServeMux matches hosts exactly and
//     cannot express a wildcard subdomain — so a tenant host is not something
//     the route table can describe. It reads the host and the headers and
//     records which workspace the request is ABOUT.
//
//   - Scoped is an app.Handler on a route group. It runs after authentication,
//     which it must, because deciding whether the caller may have that
//     workspace needs to know who the caller is. It authorises, then opens the
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

	"github.com/lemmego/fieldbubble/tenancy"
	"github.com/lemmego/fieldbubble/tenancy/hostname"
	"github.com/lemmego/fieldbubble/tenancy/rls"
)

type contextKey int

const (
	keyIdentification contextKey = iota
	keyBinding
	keyTx
)

// Provider installs tenant resolution.
type Provider struct {
	// Hostnames is the deployment's domain configuration. The zero value is
	// refused: resolving every host to the marketing surface because nobody
	// configured a domain is not a sensible default.
	Hostnames hostname.Config

	// Registry resolves identifiers and memberships.
	Registry tenancy.Registry

	// DB is the handle tenant transactions are opened on.
	DB *orm.DB

	// Principal returns who is making the request, or false when nobody is
	// authenticated. Supplied by the application, because this package must
	// not learn what a session is.
	Principal func(app.Context) (tenancy.Principal, bool)

	// SkipPrefixes are paths that never need a workspace: built assets,
	// health checks. Resolution is cheap but not free, and a transaction per
	// static file is neither.
	SkipPrefixes []string
}

var _ app.Provider = (*Provider)(nil)

func (p *Provider) Provide(a app.App) error {
	if p.Hostnames.AppDomain == "" {
		return errors.New("tenancy: no APP_DOMAIN configured; every host would resolve to the marketing surface")
	}
	if p.Registry == nil {
		return errors.New("tenancy: no Registry configured")
	}
	if p.DB == nil {
		return errors.New("tenancy: no DB configured")
	}
	if p.Hostnames.Reserved == nil {
		p.Hostnames.Reserved = hostname.DefaultReserved()
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
	// One cookie on .fieldbubble.com would be sent to every tenant
	// subdomain, so acme's session would travel to globex and the
	// per-subdomain isolation this whole design assumes would be gone — in
	// one configuration value, silently, with every test still passing.
	if domain := a.Config().Get("session.domain", ""); domain != "" {
		return fmt.Errorf(
			"tenancy: session.domain is %q and must be empty: a cookie scoped to a "+
				"parent domain is sent to every tenant subdomain, which ends session "+
				"isolation between workspaces", domain)
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

			identification, err := tenancy.Identify(r, p.Hostnames)
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
					// two workspaces, or contradicts the host it reached, is
					// either broken or probing.
					slog.WarnContext(r.Context(), "tenancy: refused a workspace identifier",
						"error", err, "host", r.Host, "path", r.URL.Path)
					http.Error(w, "bad request", http.StatusBadRequest)
				default:
					http.NotFound(w, r)
				}
				return
			}

			next.ServeHTTP(w, r.WithContext(
				context.WithValue(r.Context(), keyIdentification, identification)))
		})
	}
}

// Scoped authorises the workspace and opens the request's tenant transaction.
//
// Put it on every route group that touches tenant data, after authentication.
// Everything downstream — the rest of the chain, the handler, the renderer —
// runs inside one transaction, which is what lets the database enforce the
// same workspace the ORM does.
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

	binding, err := tenancy.Authorize(c.RequestContext(), p.Registry, identification, principal)
	if err != nil {
		switch {
		case errors.Is(err, tenancy.ErrNoWorkspace):
			// The same answer for "no such workspace" and "not yours", so
			// the response cannot be used to enumerate which companies are
			// customers.
			return c.NotFound(err)
		case errors.Is(err, tenancy.ErrNoPrincipal):
			return c.Unauthorized(err)
		case errors.Is(err, tenancy.ErrUnavailable), errors.Is(err, tenancy.ErrAmbiguous):
			return c.BadRequest(err)
		default:
			// A registry failure is NOT a 404. A database that is down must
			// not look like a workspace that does not exist.
			return c.InternalServerError(err)
		}
	}

	readOnly := c.Request().Method == http.MethodGet ||
		c.Request().Method == http.MethodHead ||
		c.Request().Method == http.MethodOptions

	return p.DB.TenantTxOptions(c.RequestContext(), binding.Workspace.ID,
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
// 404 rather than 403: sys.fieldbubble.com must not confirm that a console
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

// SurfaceOf returns the surface the request arrived on.
func SurfaceOf(ctx context.Context) (hostname.Surface, bool) {
	identification, ok := Identified(ctx)
	return identification.Surface, ok
}

// Current returns the authorised workspace, set only inside Scoped.
func Current(ctx context.Context) (tenancy.Workspace, bool) {
	binding, ok := ctx.Value(keyBinding).(tenancy.Binding)
	return binding.Workspace, ok
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

// SetLocal is re-exported so an application that opens its own tenant
// transaction scopes the database the same way this package does.
var SetLocal = rls.SetLocal
