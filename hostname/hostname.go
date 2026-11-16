// Package hostname turns a request's Host header into a surface and, when the
// host names a workspace, its slug.
//
// It is pure: no database, no cache, no HTTP. That is deliberate, because this
// is the function that decides whether a request is talking to the platform,
// to a customer's console, or to one tenant — and a decision that important
// should be exhaustively testable without a fixture.
package hostname

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// Surface is which of the application's faces a request arrived on.
type Surface uint8

const (
	SurfaceUnknown Surface = iota

	// SurfaceMarketing is the bare apex: fieldbubble.com.
	SurfaceMarketing

	// SurfacePlatform is sys.fieldbubble.com, for the people who run the
	// platform.
	SurfacePlatform

	// SurfaceConsole is app.fieldbubble.com, where a customer signs in and
	// sees the workspaces they own.
	SurfaceConsole

	// SurfaceWorkspace is acme.fieldbubble.com: one tenant.
	SurfaceWorkspace
)

func (s Surface) String() string {
	switch s {
	case SurfaceMarketing:
		return "marketing"
	case SurfacePlatform:
		return "platform"
	case SurfaceConsole:
		return "console"
	case SurfaceWorkspace:
		return "workspace"
	}
	return "unknown"
}

var (
	// ErrUnknownHost means the host is not this application's domain, or is
	// nested deeper than one label below it.
	ErrUnknownHost = errors.New("hostname: not this application's domain")

	// ErrReserved means the label is one nobody may register.
	ErrReserved = errors.New("hostname: reserved label")

	// ErrMalformed means the host could not be read as a hostname at all.
	ErrMalformed = errors.New("hostname: malformed host")
)

// Config is the one piece of deployment knowledge this package needs.
type Config struct {
	// AppDomain is the bare domain, no scheme and no port:
	// "fieldbubble.localhost" in development, "fieldbubble.com" in
	// production. It is the ONLY thing that differs between the two, which
	// is why there is no development branch anywhere below.
	AppDomain string

	// PlatformLabel and ConsoleLabel default to "sys" and "app".
	PlatformLabel string
	ConsoleLabel  string

	// Reserved labels nobody may register as a workspace.
	Reserved map[string]struct{}
}

func (c Config) platformLabel() string {
	if c.PlatformLabel == "" {
		return "sys"
	}
	return c.PlatformLabel
}

func (c Config) consoleLabel() string {
	if c.ConsoleLabel == "" {
		return "app"
	}
	return c.ConsoleLabel
}

// Result is what a host resolved to.
type Result struct {
	Surface Surface

	// Slug is the workspace label, set only for SurfaceWorkspace.
	Slug string
}

// Resolve reads a Host header.
//
// The port is stripped, so :8083 in development changes nothing.
func Resolve(rawHost string, cfg Config) (Result, error) {
	if cfg.AppDomain == "" {
		return Result{}, fmt.Errorf("%w: no app domain configured", ErrMalformed)
	}

	host, err := normalise(rawHost)
	if err != nil {
		return Result{}, err
	}
	domain := strings.ToLower(strings.TrimSuffix(cfg.AppDomain, "."))

	if host == domain {
		return Result{Surface: SurfaceMarketing}, nil
	}

	// Both conditions are needed, and the second is the one that matters.
	//
	// A suffix test alone accepts evil.acme.fieldbubble.com, and a naive
	// prefix-strip would then read the label as "evil.acme" — or, worse,
	// somebody "helpfully" takes the first label and serves acme's data to a
	// host acme does not control. Requiring exactly one more label than the
	// app domain refuses the whole shape.
	//
	// Comparing label DEPTH rather than string length is also what makes
	// fieldbubble.localhost (2 labels) and fieldbubble.com (2 labels) behave
	// identically, so there is no development special case to get wrong.
	if !strings.HasSuffix(host, "."+domain) {
		return Result{}, fmt.Errorf("%w: %q", ErrUnknownHost, host)
	}
	if labels(host) != labels(domain)+1 {
		return Result{}, fmt.Errorf("%w: %q is nested below %q", ErrUnknownHost, host, domain)
	}

	label := host[:len(host)-len(domain)-1]
	switch label {
	case cfg.platformLabel():
		return Result{Surface: SurfacePlatform}, nil
	case cfg.consoleLabel():
		return Result{Surface: SurfaceConsole}, nil
	}
	if _, taken := cfg.Reserved[label]; taken {
		return Result{}, fmt.Errorf("%w: %q", ErrReserved, label)
	}

	// Deliberately NOT validated against the slug pattern here. A host that
	// looks like a slug but names no workspace is a 404 from the registry,
	// and the pattern is a rule about what may be *created*. Enforcing it in
	// two places means maintaining two copies that will one day disagree.
	return Result{Surface: SurfaceWorkspace, Slug: label}, nil
}

// normalise lowercases, strips the port and the root dot, and rejects
// anything that is not a hostname.
func normalise(rawHost string) (string, error) {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return "", fmt.Errorf("%w: empty", ErrMalformed)
	}

	// SplitHostPort only succeeds when there is a port, and fails for a bare
	// host — so its error is not interesting, only its success.
	if stripped, _, err := net.SplitHostPort(host); err == nil && stripped != "" {
		host = stripped
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// A trailing dot is legal in DNS and is stripped above; everything below
	// is not a hostname and has no business reaching tenant resolution.
	if host == "" || strings.ContainsAny(host, " \t/\\@_:?#") {
		return "", fmt.Errorf("%w: %q", ErrMalformed, rawHost)
	}
	if strings.Contains(host, "..") {
		return "", fmt.Errorf("%w: %q", ErrMalformed, rawHost)
	}
	return host, nil
}

func labels(host string) int { return strings.Count(host, ".") + 1 }

// DefaultReserved is a starting list of labels nobody may register.
//
// It is long on purpose. Each entry is either a surface we serve, a hostname
// somebody will expect to be ours, or a name that would let a workspace
// impersonate the platform in an email or a support conversation.
func DefaultReserved() map[string]struct{} {
	labels := []string{
		"www", "api", "app", "sys", "admin", "administrator", "root",
		"mail", "smtp", "imap", "pop", "mx", "ns", "ns1", "ns2", "dns",
		"static", "assets", "cdn", "img", "images", "media", "files",
		"download", "downloads", "upload", "uploads",
		"help", "support", "docs", "doc", "status", "blog", "news",
		"billing", "pay", "payment", "payments", "checkout", "invoice", "account", "accounts",
		"login", "logout", "signin", "signup", "register", "auth", "oauth", "sso", "saml",
		"webhook", "webhooks", "callback", "callbacks",
		"my", "me", "go", "dev", "develop", "staging", "stage", "test", "testing",
		"demo", "sandbox", "preview", "local", "localhost",
		"mobile", "ws", "wss", "socket", "sockets", "queue", "worker", "workers",
		"metrics", "health", "healthz", "grafana", "prometheus", "kibana",
		"fieldbubble", "security", "abuse", "postmaster", "hostmaster", "webmaster", "noc",
		"legal", "privacy", "terms", "trust", "noreply", "no-reply",
	}
	reserved := make(map[string]struct{}, len(labels))
	for _, label := range labels {
		reserved[label] = struct{}{}
	}
	return reserved
}
