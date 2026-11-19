package tenancy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lemmego/tenancy/hostname"
)

func cfg() Config {
	return Config{Hostnames: hostname.Config{
		AppDomain: "example.localhost", Reserved: hostname.DefaultReserved(),
	}}
}

func request(host string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestTheHostNamesTheTenant(t *testing.T) {
	got, err := Identify(request("acme.example.localhost:8083", nil), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Surface != hostname.SurfaceTenant {
		t.Fatalf("surface = %v", got.Surface)
	}
	if got.Tenant.Kind != KindSlug || got.Tenant.Value != "acme" {
		t.Fatalf("tenant = %+v", got.Tenant)
	}
	if got.Tenant.Source != SourceHost {
		t.Fatalf("source = %v, want host", got.Tenant.Source)
	}
}

// The client sets the header from the URL, so the normal case is a header
// that simply restates the host.
func TestAHeaderThatRestatesTheHostIsAccepted(t *testing.T) {
	got, err := Identify(request("acme.example.localhost", map[string]string{DefaultSlugHeader: "acme"}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant.Value != "acme" {
		t.Fatalf("tenant = %+v", got.Tenant)
	}
	// The host is recorded as the source even though a header agreed, because
	// the host is what was actually trusted.
	if got.Tenant.Source != SourceHost {
		t.Fatalf("source = %v, want host", got.Tenant.Source)
	}
}

// The case this rule exists for: a page served from acme asks for globex
// while acme's session cookie rides along automatically.
func TestAHeaderMayNotOverrideTheHost(t *testing.T) {
	_, err := Identify(request("acme.example.localhost", map[string]string{DefaultSlugHeader: "globex"}), cfg())
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
}

func TestBothHeadersTogetherAreRefused(t *testing.T) {
	_, err := Identify(request("app.example.localhost", map[string]string{
		DefaultSlugHeader: "acme",
		DefaultIDHeader:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	}), cfg())
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
}

func TestAnIDHeaderOnATenantHostDefersToTheHost(t *testing.T) {
	got, err := Identify(request("acme.example.localhost", map[string]string{
		DefaultIDHeader: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant.Kind != KindSlug || got.Tenant.Value != "acme" {
		t.Fatalf("the host must win: %+v", got.Tenant)
	}
	// A uuid cannot be compared to a slug without a lookup, so the check is
	// handed on rather than dropped.
	if got.Tenant.MustAgreeWith != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Fatalf("the id was dropped instead of deferred: %+v", got.Tenant)
	}
}

func TestOffATenantHostTheHeaderIsTheOnlySource(t *testing.T) {
	for _, host := range []string{"app.example.localhost", "sys.example.localhost"} {
		got, err := Identify(request(host, map[string]string{DefaultSlugHeader: "acme"}), cfg())
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.Tenant.Value != "acme" || got.Tenant.Source != SourceHeader {
			t.Fatalf("%s: tenant = %+v", host, got.Tenant)
		}
	}
}

func TestNoHeaderOffATenantHostNamesNoTenant(t *testing.T) {
	got, err := Identify(request("app.example.localhost", nil), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Tenant.IsZero() {
		t.Fatalf("want no tenant, got %+v", got.Tenant)
	}
}

// A malformed header is a 400 before it reaches the database or a cache key.
func TestAMalformedHeaderIsRefused(t *testing.T) {
	bad := map[string]map[string]string{
		"slug too short":     {DefaultSlugHeader: "ab"},
		"slug too long":      {DefaultSlugHeader: "abcdefghijklmnopqrstuvwxyz0123456789"},
		"slug with a dot":    {DefaultSlugHeader: "acme.globex"},
		"slug with a slash":  {DefaultSlugHeader: "acme/../globex"},
		"slug with a colon":  {DefaultSlugHeader: "acme:globex"},
		"slug with a quote":  {DefaultSlugHeader: "acme'--"},
		"slug leading dash":  {DefaultSlugHeader: "-acme"},
		"slug trailing dash": {DefaultSlugHeader: "acme-"},
		"id not a uuid":      {DefaultIDHeader: "not-a-uuid"},
		"id too short":       {DefaultIDHeader: "6ba7b810-9dad-11d1-80b4-00c04fd430c"},
		"id with a quote":    {DefaultIDHeader: "6ba7b810-9dad-11d1-80b4-00c04fd430c'"},
	}
	for name, headers := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := Identify(request("app.example.localhost", headers), cfg())
			if !errors.Is(err, ErrBadIdentifier) && !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("want a refusal, got %v", err)
			}
		})
	}
}

func TestIdentifiersAreLowercased(t *testing.T) {
	got, err := Identify(request("app.example.localhost", map[string]string{DefaultSlugHeader: "ACME"}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Tenant.Value != "acme" {
		t.Fatalf("value = %q, want lowercased", got.Tenant.Value)
	}
}

// An unknown or reserved host never reaches tenant resolution at all.
func TestAnUnknownHostIsRefusedBeforeAnyHeaderIsRead(t *testing.T) {
	_, err := Identify(request("evil.acme.example.localhost", map[string]string{DefaultSlugHeader: "acme"}), cfg())
	if !errors.Is(err, hostname.ErrUnknownHost) {
		t.Fatalf("want ErrUnknownHost, got %v", err)
	}
}
