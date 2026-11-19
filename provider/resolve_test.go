package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lemmego/tenancy"
	"github.com/lemmego/tenancy/hostname"
)

// The HTTPMiddleware half, which is testable as ordinary HTTP because that is
// all it is.

// fakeRegistry knows two tenants and nothing else.
//
// Lookup is what Resolve calls; IsMember belongs to Scoped and is not
// reached by any test in this file, which is the point of the split.
type fakeRegistry struct {
	tenants map[string]tenancy.Tenant
	err     error // when set, every lookup fails this way
}

func (r fakeRegistry) Lookup(_ context.Context, id tenancy.Identifier) (tenancy.Tenant, error) {
	if r.err != nil {
		return tenancy.Tenant{}, r.err
	}
	tenant, ok := r.tenants[strings.ToLower(id.Value)]
	if !ok {
		return tenancy.Tenant{}, tenancy.ErrNoTenant
	}
	return tenant, nil
}

func (r fakeRegistry) IsMember(context.Context, string, tenancy.Principal) (bool, error) {
	return false, errors.New("IsMember must not be reached from the HTTP middleware")
}

func testProvider() *Provider {
	return &Provider{
		Config: tenancy.Config{Hostnames: hostname.Config{
			AppDomain: "example.localhost",
			Reserved:  hostname.DefaultReserved(),
		}},
		Registry: fakeRegistry{tenants: map[string]tenancy.Tenant{
			"acme": {ID: "11111111-1111-1111-1111-111111111111", Slug: "acme",
				Name: "Acme", Status: tenancy.StatusActive},
			"globex": {ID: "22222222-2222-2222-2222-222222222222", Slug: "globex",
				Name: "Globex", Status: tenancy.StatusActive},
		}},
		SkipPrefixes: []string{"/build/", "/health"},
	}
}

// serve runs a request through resolve and reports what the handler saw.
//
// ran and identified are tracked separately on purpose: a skipped prefix
// reaches the handler WITHOUT an identification, so collapsing the two would
// make "the handler ran" and "a tenant was resolved" indistinguishable —
// and the skip path is precisely the case where they differ.
func serve(t *testing.T, p *Provider, host, path string, headers map[string]string) (recorder *httptest.ResponseRecorder, seen tenancy.Identification, identified, ran bool) {
	t.Helper()

	handler := p.resolve()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ran = true
		seen, identified = Identified(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Host = host
	for k, v := range headers {
		request.Header.Set(k, v)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder, seen, identified, ran
}

func TestResolveRecordsTheTenantForATenantHost(t *testing.T) {
	recorder, identification, ok, _ := serve(t, testProvider(), "acme.example.localhost:8083", "/", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !ok {
		t.Fatal("the handler saw no identification")
	}
	if identification.Surface != hostname.SurfaceTenant {
		t.Fatalf("surface = %v", identification.Surface)
	}
	if identification.Tenant.Value != "acme" || identification.Tenant.Source != tenancy.SourceHost {
		t.Fatalf("tenant = %+v", identification.Tenant)
	}
}

// Resolve also SELECTS the tenant for a host, which is what makes a user
// lookup possible before authentication.
func TestResolveSelectsTheTenantForAHost(t *testing.T) {
	var selected tenancy.Tenant
	var ok bool

	handler := testProvider().resolve()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		selected, ok = Selected(r.Context())
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Host = "acme.example.localhost"
	handler.ServeHTTP(httptest.NewRecorder(), request)

	if !ok {
		t.Fatal("no tenant was selected, so a user lookup would find nobody")
	}
	if selected.ID != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("selected %+v", selected)
	}
}

func TestResolveRecordsTheHeaderOnTheConsoleSurface(t *testing.T) {
	_, identification, ok, _ := serve(t, testProvider(), "app.example.localhost", "/account",
		map[string]string{tenancy.DefaultSlugHeader: "acme"})
	if !ok {
		t.Fatal("no identification")
	}
	if identification.Surface != hostname.SurfaceConsole {
		t.Fatalf("surface = %v", identification.Surface)
	}
	if identification.Tenant.Source != tenancy.SourceHeader {
		t.Fatalf("source = %v, want header so the cache keys it separately", identification.Tenant.Source)
	}
}

// An unknown or reserved host is a 404, and the handler is never reached —
// so nothing downstream can accidentally serve a request with no tenant.
func TestResolveRefusesAHostThatIsNotOurs(t *testing.T) {
	for name, host := range map[string]string{
		"another domain":   "acme.example.com",
		"nested deeper":    "evil.acme.example.localhost",
		"a reserved label": "api.example.localhost",
		"not a hostname":   "ac me.example.localhost",
	} {
		t.Run(name, func(t *testing.T) {
			recorder, _, _, reached := serve(t, testProvider(), host, "/", nil)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", recorder.Code)
			}
			if reached {
				t.Fatal("the handler ran for a host that does not resolve")
			}
		})
	}
}

// A client that names two tenants, or contradicts the host it reached, is
// a 400 rather than a 404: it is a broken client or a probe, not a missing
// tenant, and the difference is what makes it findable in a log.
func TestResolveRefusesAContradictoryRequestWithFourHundred(t *testing.T) {
	for name, tc := range map[string]struct {
		host    string
		headers map[string]string
	}{
		"header disagrees with the host": {
			host:    "acme.example.localhost",
			headers: map[string]string{tenancy.DefaultSlugHeader: "globex"},
		},
		"two tenant headers": {
			host: "app.example.localhost",
			headers: map[string]string{
				tenancy.DefaultSlugHeader: "acme",
				tenancy.DefaultIDHeader:   "11111111-1111-1111-1111-111111111111",
			},
		},
		"a malformed identifier": {
			host:    "app.example.localhost",
			headers: map[string]string{tenancy.DefaultIDHeader: "not-a-uuid"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			recorder, _, _, reached := serve(t, testProvider(), tc.host, "/", tc.headers)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", recorder.Code)
			}
			if reached {
				t.Fatal("the handler ran for a contradictory request")
			}
		})
	}
}

// Built assets must not pay for resolution, and must not 404 on a host that
// does not resolve — the marketing site serves them from the apex.
// A well-formed tenant host that names no tenant is a 404 — an unknown
// subdomain, which is what it is.
func TestResolveRefusesAHostThatNamesNoTenant(t *testing.T) {
	recorder, _, _, ran := serve(t, testProvider(), "nosuchtenant.example.localhost", "/", nil)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if ran {
		t.Fatal("the handler ran for a tenant that does not exist")
	}
}

// And the distinction that matters more: a registry that is DOWN is a 503,
// never a 404. A database outage that presents as "no such tenant" gets
// diagnosed as a DNS problem for two hours.
func TestAFailedLookupIsUnavailableAndNotMissing(t *testing.T) {
	p := testProvider()
	p.Registry = fakeRegistry{err: errors.New("connection refused")}

	recorder, _, _, ran := serve(t, p, "acme.example.localhost", "/", nil)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: an outage must not look like a missing tenant", recorder.Code)
	}
	if ran {
		t.Fatal("the handler ran with no tenant resolved")
	}
}

// A header-named tenant is deliberately NOT resolved here, so the 404 and
// the non-member answer stay indistinguishable in Scoped.
func TestResolveLeavesAHeaderNamedTenantUnresolved(t *testing.T) {
	p := testProvider()
	p.Registry = fakeRegistry{err: errors.New("this must not be called")}

	recorder, _, identified, ran := serve(t, p, "app.example.localhost", "/account",
		map[string]string{tenancy.DefaultSlugHeader: "acme"})

	if recorder.Code != http.StatusOK || !ran || !identified {
		t.Fatalf("a header-named tenant must pass through unresolved: status %d, ran %v, identified %v",
			recorder.Code, ran, identified)
	}
}

func TestResolveSkipsTheConfiguredPrefixes(t *testing.T) {
	recorder, _, identified, ran := serve(t, testProvider(), "anything.example.com", "/build/app-abc123.js", nil)

	if recorder.Code != http.StatusOK || !ran {
		t.Fatalf("a skipped prefix must pass straight through: status %d, ran %v", recorder.Code, ran)
	}
	// And it must carry NO tenant, because resolution never happened.
	// Anything downstream that needs one has to say so rather than assume.
	if identified {
		t.Fatal("a skipped request carries an identification, so resolution was not actually skipped")
	}
}

func TestResolveRefusesToStartWithoutADomain(t *testing.T) {
	p := &Provider{Registry: nil}
	if err := p.Provide(nil); err == nil {
		t.Fatal("a provider with no app domain must refuse to start: every host would " +
			"otherwise resolve to the marketing surface")
	}
}
