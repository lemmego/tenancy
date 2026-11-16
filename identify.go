package tenancy

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/lemmego/fieldbubble/tenancy/hostname"
)

// How a request says which workspace it means.
//
// There are two ways, and the difference between them is the whole of this
// file:
//
//   - The HOST. acme.fieldbubble.com names acme. A browser cannot forge this
//     — it is where the request went, and the session cookie that came with
//     it is scoped to that exact host.
//
//   - A HEADER. X-Workspace-User: acme, or X-Workspace-ID: <uuid>. This is
//     for an API client that does not have a per-tenant host to talk to, and
//     for a mobile app that knows which workspace it signed into.
//
// # A header selects; it does not authorise
//
// This is the important part. A header is client-supplied input, so on its
// own it says nothing about whether the caller may see that workspace. Taking
// the tenant from a header and scoping the query to it — with nothing else —
// means any authenticated member of one workspace can read another by typing
// its id, and both the ORM predicate and the row-level security policy will
// enforce that choice perfectly. The isolation machinery is not the thing
// that protects you here.
//
// So Identify answers only "which workspace is this request *about*". The
// binding is then derived from the caller's MEMBERSHIP of that workspace —
// see Authorize — and a caller who names a workspace they do not belong to
// gets the same answer as one who names a workspace that does not exist.
const (
	// HeaderSlug carries the subdomain label: "acme" means
	// acme.fieldbubble.com.
	HeaderSlug = "X-Workspace-User"

	// HeaderID carries the workspace's uuid.
	HeaderID = "X-Workspace-ID"
)

// Source is where the identifier came from. It is carried through to the
// cache, which keys each source separately: conflating them means a
// header-resolved request can poison a host-resolved entry, and that is a
// tenant leak rather than a cache bug.
type Source uint8

const (
	SourceNone Source = iota
	SourceHost
	SourceHeader
)

func (s Source) String() string {
	switch s {
	case SourceHost:
		return "host"
	case SourceHeader:
		return "header"
	}
	return "none"
}

// Kind is which identifier was given.
type Kind uint8

const (
	KindNone Kind = iota
	KindSlug
	KindID
)

func (k Kind) String() string {
	switch k {
	case KindSlug:
		return "slug"
	case KindID:
		return "id"
	}
	return "none"
}

// Identifier names a workspace, without yet saying whether the caller may
// have it.
type Identifier struct {
	Kind   Kind
	Value  string
	Source Source

	// MustAgreeWith is set when a request arrived on a workspace host AND
	// carried an id header. The host wins, and the registry must additionally
	// confirm the resolved workspace has this id — a comparison that needs a
	// lookup and so cannot happen here. Empty when there is nothing to check.
	MustAgreeWith string
}

func (i Identifier) IsZero() bool { return i.Kind == KindNone }

// Identification is the result of reading a request.
type Identification struct {
	Surface hostname.Surface

	// Workspace is zero on the platform, console and marketing surfaces,
	// unless a header named one.
	Workspace Identifier
}

var (
	// ErrAmbiguous means the request named more than one workspace, or named
	// one that disagrees with the host it arrived on.
	ErrAmbiguous = errors.New("tenancy: the request names more than one workspace")

	// ErrBadIdentifier means a header was present but unusable.
	ErrBadIdentifier = errors.New("tenancy: unusable workspace identifier")
)

// Identify reads the host and the headers and returns the one workspace this
// request is about.
//
// The rules, and the reasoning for each:
//
//  1. The host decides the surface. Always.
//
//  2. At most one workspace header. Both present is a client bug, and
//     guessing which one was meant is how a client that sets them from two
//     different places ends up reading the wrong tenant for a month.
//
//  3. On a workspace host, a header must AGREE with the host. A browser sends
//     its cookie to acme.fieldbubble.com automatically; if a header could
//     override the tenant from there, a page on acme could ask for globex
//     with acme's credentials attached. The membership check would still
//     refuse it, but this refuses it earlier and without a database lookup.
//     A slug header is compared directly here; an id header can only be
//     compared after resolution, so that comparison belongs to the registry.
//
//  4. Off a workspace host, the header is the only source — which is exactly
//     why Authorize exists.
func Identify(r *http.Request, cfg hostname.Config) (Identification, error) {
	host, err := hostname.Resolve(r.Host, cfg)
	if err != nil {
		return Identification{}, err
	}

	header, err := identifierFromHeaders(r.Header)
	if err != nil {
		return Identification{}, err
	}

	result := Identification{Surface: host.Surface}

	if host.Surface == hostname.SurfaceWorkspace {
		fromHost := Identifier{Kind: KindSlug, Value: host.Slug, Source: SourceHost}

		switch {
		case header.IsZero():
			result.Workspace = fromHost

		case header.Kind == KindSlug:
			// Comparable now, so compare now.
			if header.Value != host.Slug {
				return Identification{}, fmt.Errorf(
					"%w: host says %q, %s says %q",
					ErrAmbiguous, host.Slug, HeaderSlug, header.Value)
			}
			result.Workspace = fromHost

		default:
			// An id header on a workspace host. It cannot be compared
			// without a lookup, so the host wins and the registry is told to
			// check the id against it — see MustAgreeWith.
			result.Workspace = fromHost
			result.Workspace.MustAgreeWith = header.Value
		}
		return result, nil
	}

	// Platform, console or marketing. A header is the only way such a request
	// can be about a workspace at all.
	result.Workspace = header
	return result, nil
}

// identifierFromHeaders reads at most one workspace header.
func identifierFromHeaders(h http.Header) (Identifier, error) {
	slug := strings.TrimSpace(h.Get(HeaderSlug))
	id := strings.TrimSpace(h.Get(HeaderID))

	switch {
	case slug != "" && id != "":
		return Identifier{}, fmt.Errorf("%w: both %s and %s are set", ErrAmbiguous, HeaderSlug, HeaderID)

	case slug != "":
		if !looksLikeSlug(slug) {
			return Identifier{}, fmt.Errorf("%w: %s is not a workspace label", ErrBadIdentifier, HeaderSlug)
		}
		return Identifier{Kind: KindSlug, Value: strings.ToLower(slug), Source: SourceHeader}, nil

	case id != "":
		if !looksLikeUUID(id) {
			return Identifier{}, fmt.Errorf("%w: %s is not a uuid", ErrBadIdentifier, HeaderID)
		}
		return Identifier{Kind: KindID, Value: strings.ToLower(id), Source: SourceHeader}, nil
	}
	return Identifier{}, nil
}

// looksLikeSlug and looksLikeUUID are shape checks, not authorisation and not
// existence. They exist so that a malformed header is a 400 before it reaches
// the database, and so that nothing resembling SQL, a path or a cache-key
// separator can travel in a cache key. Whether the workspace exists, and
// whether the caller may have it, is settled later and elsewhere.
func looksLikeSlug(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}
