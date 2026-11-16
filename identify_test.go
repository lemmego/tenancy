package tenancy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lemmego/fieldbubble/tenancy/hostname"
)

func cfg() hostname.Config {
	return hostname.Config{AppDomain: "fieldbubble.localhost", Reserved: hostname.DefaultReserved()}
}

func request(host string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestTheHostNamesTheWorkspace(t *testing.T) {
	got, err := Identify(request("acme.fieldbubble.localhost:8083", nil), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Surface != hostname.SurfaceWorkspace {
		t.Fatalf("surface = %v", got.Surface)
	}
	if got.Workspace.Kind != KindSlug || got.Workspace.Value != "acme" {
		t.Fatalf("workspace = %+v", got.Workspace)
	}
	if got.Workspace.Source != SourceHost {
		t.Fatalf("source = %v, want host", got.Workspace.Source)
	}
}

// The client sets the header from the URL, so the normal case is a header
// that simply restates the host.
func TestAHeaderThatRestatesTheHostIsAccepted(t *testing.T) {
	got, err := Identify(request("acme.fieldbubble.localhost", map[string]string{HeaderSlug: "acme"}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Workspace.Value != "acme" {
		t.Fatalf("workspace = %+v", got.Workspace)
	}
	// The host is recorded as the source even though a header agreed, because
	// the host is what was actually trusted.
	if got.Workspace.Source != SourceHost {
		t.Fatalf("source = %v, want host", got.Workspace.Source)
	}
}

// The case this rule exists for: a page served from acme asks for globex
// while acme's session cookie rides along automatically.
func TestAHeaderMayNotOverrideTheHost(t *testing.T) {
	_, err := Identify(request("acme.fieldbubble.localhost", map[string]string{HeaderSlug: "globex"}), cfg())
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
}

func TestBothHeadersTogetherAreRefused(t *testing.T) {
	_, err := Identify(request("app.fieldbubble.localhost", map[string]string{
		HeaderSlug: "acme",
		HeaderID:   "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	}), cfg())
	if !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
}

func TestAnIDHeaderOnAWorkspaceHostDefersToTheHost(t *testing.T) {
	got, err := Identify(request("acme.fieldbubble.localhost", map[string]string{
		HeaderID: "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Workspace.Kind != KindSlug || got.Workspace.Value != "acme" {
		t.Fatalf("the host must win: %+v", got.Workspace)
	}
	// A uuid cannot be compared to a slug without a lookup, so the check is
	// handed on rather than dropped.
	if got.Workspace.MustAgreeWith != "6ba7b810-9dad-11d1-80b4-00c04fd430c8" {
		t.Fatalf("the id was dropped instead of deferred: %+v", got.Workspace)
	}
}

func TestOffAWorkspaceHostTheHeaderIsTheOnlySource(t *testing.T) {
	for _, host := range []string{"app.fieldbubble.localhost", "sys.fieldbubble.localhost"} {
		got, err := Identify(request(host, map[string]string{HeaderSlug: "acme"}), cfg())
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.Workspace.Value != "acme" || got.Workspace.Source != SourceHeader {
			t.Fatalf("%s: workspace = %+v", host, got.Workspace)
		}
	}
}

func TestNoHeaderOffAWorkspaceHostNamesNoWorkspace(t *testing.T) {
	got, err := Identify(request("app.fieldbubble.localhost", nil), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Workspace.IsZero() {
		t.Fatalf("want no workspace, got %+v", got.Workspace)
	}
}

// A malformed header is a 400 before it reaches the database or a cache key.
func TestAMalformedHeaderIsRefused(t *testing.T) {
	bad := map[string]map[string]string{
		"slug too short":     {HeaderSlug: "ab"},
		"slug too long":      {HeaderSlug: "abcdefghijklmnopqrstuvwxyz0123456789"},
		"slug with a dot":    {HeaderSlug: "acme.globex"},
		"slug with a slash":  {HeaderSlug: "acme/../globex"},
		"slug with a colon":  {HeaderSlug: "acme:globex"},
		"slug with a quote":  {HeaderSlug: "acme'--"},
		"slug leading dash":  {HeaderSlug: "-acme"},
		"slug trailing dash": {HeaderSlug: "acme-"},
		"id not a uuid":      {HeaderID: "not-a-uuid"},
		"id too short":       {HeaderID: "6ba7b810-9dad-11d1-80b4-00c04fd430c"},
		"id with a quote":    {HeaderID: "6ba7b810-9dad-11d1-80b4-00c04fd430c'"},
	}
	for name, headers := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := Identify(request("app.fieldbubble.localhost", headers), cfg())
			if !errors.Is(err, ErrBadIdentifier) && !errors.Is(err, ErrAmbiguous) {
				t.Fatalf("want a refusal, got %v", err)
			}
		})
	}
}

func TestIdentifiersAreLowercased(t *testing.T) {
	got, err := Identify(request("app.fieldbubble.localhost", map[string]string{HeaderSlug: "ACME"}), cfg())
	if err != nil {
		t.Fatal(err)
	}
	if got.Workspace.Value != "acme" {
		t.Fatalf("value = %q, want lowercased", got.Workspace.Value)
	}
}

// An unknown or reserved host never reaches workspace resolution at all.
func TestAnUnknownHostIsRefusedBeforeAnyHeaderIsRead(t *testing.T) {
	_, err := Identify(request("evil.acme.fieldbubble.localhost", map[string]string{HeaderSlug: "acme"}), cfg())
	if !errors.Is(err, hostname.ErrUnknownHost) {
		t.Fatalf("want ErrUnknownHost, got %v", err)
	}
}
