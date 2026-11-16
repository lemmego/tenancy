package provider

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lemmego/fieldbubble/tenancy"
	"github.com/lemmego/fieldbubble/tenancy/hostname"
)

// The HTTPMiddleware half, which is testable as ordinary HTTP because that is
// all it is.

func testProvider() *Provider {
	return &Provider{
		Hostnames: hostname.Config{
			AppDomain: "fieldbubble.localhost",
			Reserved:  hostname.DefaultReserved(),
		},
		SkipPrefixes: []string{"/build/", "/health"},
	}
}

// serve runs a request through resolve and reports what the handler saw.
//
// ran and identified are tracked separately on purpose: a skipped prefix
// reaches the handler WITHOUT an identification, so collapsing the two would
// make "the handler ran" and "a workspace was resolved" indistinguishable —
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

func TestResolveRecordsTheWorkspaceForATenantHost(t *testing.T) {
	recorder, identification, ok, _ := serve(t, testProvider(), "acme.fieldbubble.localhost:8083", "/", nil)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	if !ok {
		t.Fatal("the handler saw no identification")
	}
	if identification.Surface != hostname.SurfaceWorkspace {
		t.Fatalf("surface = %v", identification.Surface)
	}
	if identification.Workspace.Value != "acme" || identification.Workspace.Source != tenancy.SourceHost {
		t.Fatalf("workspace = %+v", identification.Workspace)
	}
}

func TestResolveRecordsTheHeaderOnTheConsoleSurface(t *testing.T) {
	_, identification, ok, _ := serve(t, testProvider(), "app.fieldbubble.localhost", "/account",
		map[string]string{tenancy.HeaderSlug: "acme"})
	if !ok {
		t.Fatal("no identification")
	}
	if identification.Surface != hostname.SurfaceConsole {
		t.Fatalf("surface = %v", identification.Surface)
	}
	if identification.Workspace.Source != tenancy.SourceHeader {
		t.Fatalf("source = %v, want header so the cache keys it separately", identification.Workspace.Source)
	}
}

// An unknown or reserved host is a 404, and the handler is never reached —
// so nothing downstream can accidentally serve a request with no workspace.
func TestResolveRefusesAHostThatIsNotOurs(t *testing.T) {
	for name, host := range map[string]string{
		"another domain":   "acme.example.com",
		"nested deeper":    "evil.acme.fieldbubble.localhost",
		"a reserved label": "api.fieldbubble.localhost",
		"not a hostname":   "ac me.fieldbubble.localhost",
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

// A client that names two workspaces, or contradicts the host it reached, is
// a 400 rather than a 404: it is a broken client or a probe, not a missing
// tenant, and the difference is what makes it findable in a log.
func TestResolveRefusesAContradictoryRequestWithFourHundred(t *testing.T) {
	for name, tc := range map[string]struct {
		host    string
		headers map[string]string
	}{
		"header disagrees with the host": {
			host:    "acme.fieldbubble.localhost",
			headers: map[string]string{tenancy.HeaderSlug: "globex"},
		},
		"two workspace headers": {
			host: "app.fieldbubble.localhost",
			headers: map[string]string{
				tenancy.HeaderSlug: "acme",
				tenancy.HeaderID:   "11111111-1111-1111-1111-111111111111",
			},
		},
		"a malformed identifier": {
			host:    "app.fieldbubble.localhost",
			headers: map[string]string{tenancy.HeaderID: "not-a-uuid"},
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
func TestResolveSkipsTheConfiguredPrefixes(t *testing.T) {
	recorder, _, identified, ran := serve(t, testProvider(), "anything.example.com", "/build/app-abc123.js", nil)

	if recorder.Code != http.StatusOK || !ran {
		t.Fatalf("a skipped prefix must pass straight through: status %d, ran %v", recorder.Code, ran)
	}
	// And it must carry NO workspace, because resolution never happened.
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
