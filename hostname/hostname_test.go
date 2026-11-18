package hostname

import (
	"errors"
	"testing"
)

// The same table is run against a development domain and a production one,
// because the one thing this package must get right is that they behave
// identically — that is the whole reason it compares label depth instead of
// stripping a suffix.
func TestResolve(t *testing.T) {
	cases := []struct {
		host    string
		surface Surface
		slug    string
		err     error
	}{
		// The three fixed surfaces.
		{host: "{domain}", surface: SurfaceMarketing},
		{host: "sys.{domain}", surface: SurfacePlatform},
		{host: "app.{domain}", surface: SurfaceConsole},

		// A workspace.
		{host: "acme.{domain}", surface: SurfaceWorkspace, slug: "acme"},
		{host: "globex-inc.{domain}", surface: SurfaceWorkspace, slug: "globex-inc"},
		{host: "a1.{domain}", surface: SurfaceWorkspace, slug: "a1"},

		// Ports are stripped, so development changes nothing.
		{host: "acme.{domain}:8083", surface: SurfaceWorkspace, slug: "acme"},
		{host: "{domain}:8083", surface: SurfaceMarketing},
		{host: "sys.{domain}:8083", surface: SurfacePlatform},

		// Case and the legal trailing dot.
		{host: "ACME.{domain}", surface: SurfaceWorkspace, slug: "acme"},
		{host: "acme.{domain}.", surface: SurfaceWorkspace, slug: "acme"},
		{host: "  acme.{domain}  ", surface: SurfaceWorkspace, slug: "acme"},

		// The attack this function exists to refuse. A suffix test alone
		// accepts these, and then the label is read as "evil.acme" — or
		// somebody takes the first label and serves acme to a host acme does
		// not control.
		{host: "evil.acme.{domain}", err: ErrUnknownHost},
		{host: "a.b.c.{domain}", err: ErrUnknownHost},

		// Not our domain at all, including the lookalikes.
		{host: "acme.example.com", err: ErrUnknownHost},
		{host: "{domain}.evil.com", err: ErrUnknownHost},
		{host: "notfieldbubble.com", err: ErrUnknownHost},

		// Reserved.
		{host: "www.{domain}", err: ErrReserved},
		{host: "api.{domain}", err: ErrReserved},
		{host: "admin.{domain}", err: ErrReserved},

		// Not hostnames.
		{host: "", err: ErrMalformed},
		{host: "acme..{domain}", err: ErrMalformed},
		{host: "ac me.{domain}", err: ErrMalformed},
		{host: "acme.{domain}/../x", err: ErrMalformed},
		{host: "user@acme.{domain}", err: ErrMalformed},
	}

	for _, domain := range []string{"fieldbubble.localhost", "fieldbubble.com", "fb.co.uk"} {
		cfg := Config{AppDomain: domain, Reserved: DefaultReserved()}
		for _, tc := range cases {
			host := subst(tc.host, domain)
			t.Run(domain+"/"+host, func(t *testing.T) {
				got, err := Resolve(host, cfg)
				if tc.err != nil {
					if !errors.Is(err, tc.err) {
						t.Fatalf("want %v, got result %+v err %v", tc.err, got, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Surface != tc.surface {
					t.Errorf("surface = %v, want %v", got.Surface, tc.surface)
				}
				if got.Slug != tc.slug {
					t.Errorf("slug = %q, want %q", got.Slug, tc.slug)
				}
			})
		}
	}
}

func subst(host, domain string) string {
	out := ""
	for {
		i := indexOf(host, "{domain}")
		if i < 0 {
			return out + host
		}
		out += host[:i] + domain
		host = host[i+len("{domain}"):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// A deployment that forgot to configure its domain must not resolve
// everything to the marketing surface.
func TestAnUnconfiguredDomainResolvesNothing(t *testing.T) {
	if _, err := Resolve("acme.fieldbubble.com", Config{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

// The labels are configurable, and a workspace may not take one.
func TestTheSurfaceLabelsAreConfigurable(t *testing.T) {
	cfg := Config{AppDomain: "fieldbubble.com", PlatformLabel: "ops", ConsoleLabel: "portal"}

	for host, want := range map[string]Surface{
		"ops.fieldbubble.com":    SurfacePlatform,
		"portal.fieldbubble.com": SurfaceConsole,
		// With the labels moved, the defaults are ordinary labels again —
		// which is why the reserved list, not this switch, is what stops a
		// workspace calling itself "app".
		"sys.fieldbubble.com": SurfaceWorkspace,
		"app.fieldbubble.com": SurfaceWorkspace,
	} {
		got, err := Resolve(host, cfg)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		if got.Surface != want {
			t.Errorf("%s resolved to %v, want %v", host, got.Surface, want)
		}
	}
}

// A label is registrable exactly when a host made from it resolves back to a
// workspace with that slug — which is why ValidateLabel calls Resolve
// instead of keeping its own copy of the rules.
func TestValidateLabel(t *testing.T) {
	cfg := Config{AppDomain: "fieldbubble.localhost", Reserved: DefaultReserved()}

	for _, tc := range []struct {
		raw  string
		want string
		err  error
	}{
		{raw: "acme", want: "acme"},
		{raw: "globex-inc", want: "globex-inc"},
		{raw: "a1b", want: "a1b"},
		{raw: "abc", want: "abc"},
		{raw: "a12345678901234567890123456789012", err: ErrBadLabel}, // 33
		{raw: "a1234567890123456789012345678901", want: "a1234567890123456789012345678901"},

		// Canonicalised rather than refused: somebody typing "ACME " into a
		// form has not made a mistake worth a message.
		{raw: "ACME", want: "acme"},
		{raw: "  acme  ", want: "acme"},

		// Shape.
		{raw: "", err: ErrBadLabel},
		{raw: "ab", err: ErrBadLabel},
		{raw: "-acme", err: ErrBadLabel},
		{raw: "acme-", err: ErrBadLabel},
		{raw: "ac_me", err: ErrBadLabel},
		{raw: "ac.me", err: ErrBadLabel},
		{raw: "ac me", err: ErrBadLabel},
		{raw: "acmé", err: ErrBadLabel},

		// Reserved, from the list.
		{raw: "www", err: ErrReserved},
		{raw: "admin", err: ErrReserved},
		{raw: "api", err: ErrReserved},

		// Reserved because they are surfaces. These are in the default list
		// too, which is why the next test moves them.
		{raw: "sys", err: ErrReserved},
		{raw: "app", err: ErrReserved},
	} {
		got, err := ValidateLabel(tc.raw, cfg)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("ValidateLabel(%q) = %q, %v; want %v", tc.raw, got, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ValidateLabel(%q): %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ValidateLabel(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// The case a hand-written copy of the rules would miss: a configured surface
// label is not in the reserved list, and a workspace registered under it
// would be a workspace nobody can reach, because Resolve answers the surface
// first.
func TestAConfiguredSurfaceLabelIsNotRegistrable(t *testing.T) {
	cfg := Config{
		AppDomain:     "fieldbubble.com",
		PlatformLabel: "ops",
		ConsoleLabel:  "portal",
		// Deliberately empty: nothing but the surface labels themselves can
		// make these unregistrable, which is the point.
		Reserved: map[string]struct{}{},
	}

	for _, label := range []string{"ops", "portal"} {
		if got, err := ValidateLabel(label, cfg); !errors.Is(err, ErrReserved) {
			t.Errorf("ValidateLabel(%q) = %q, %v; want ErrReserved", label, got, err)
		}
	}
	// And with the labels moved, the defaults are ordinary labels again.
	for _, label := range []string{"sys", "app"} {
		if got, err := ValidateLabel(label, cfg); err != nil || got != label {
			t.Errorf("ValidateLabel(%q) = %q, %v; want it registrable", label, got, err)
		}
	}
}
