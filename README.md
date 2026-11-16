# tenancy

Decides which workspace a request is about, and whether the caller may have it.

Two steps, deliberately separate:

```go
ident, err := tenancy.Identify(r, hostCfg)              // which workspace is named?
binding, err := tenancy.Authorize(ctx, reg, ident, who) // may this caller have it?
```

`binding.Workspace.ID` is then the one value every query, every row-level
security policy and every cache key for that request is scoped by.

## How a request names a workspace

| | Example | Trust |
|---|---|---|
| Host | `acme.fieldbubble.com` | Where the request actually went. A browser cannot forge it, and the session cookie is scoped to that exact host. |
| `X-Workspace-User` | `acme` — the subdomain label | Client-supplied. |
| `X-Workspace-ID` | `11111111-…` — the workspace uuid | Client-supplied. |

The host resolution compares **label depth** against one configured
`APP_DOMAIN`, which is why `fieldbubble.localhost` and `fieldbubble.com`
behave identically and there is no development branch anywhere. It also
refuses `evil.acme.fieldbubble.com`, which a suffix test alone accepts and a
naive prefix-strip then reads as the workspace `evil.acme` — or, worse, as
`acme`.

## A header selects. It does not authorise.

This is the whole point of the package, so it is worth being blunt about.

A request carrying `X-Workspace-User: globex` has said a word. On its own that
word means nothing about whether the caller may see globex. If the tenant is
taken from a header and handed straight to the query scope, then **any
authenticated member of one workspace can read another by typing its name** —
and the ORM's tenant predicate and the database's row-level security policy
will both enforce that choice perfectly. The isolation machinery is not what
protects you here; it is what faithfully carries out whatever it was told.

Using the slug instead of the uuid does not help. A slug is *more* guessable:
it is public, it is in the URL, and it is usually the company's name.

So `Authorize` derives the binding from the caller's **membership** of the
resolved workspace, never from the name. Two consequences fall out:

- A caller who names a workspace they do not belong to is refused with
  `ErrNoWorkspace` — **the same error as a workspace that does not exist**. A
  distinct "forbidden" would confirm which companies are customers and let
  anybody enumerate the tenant list from a login page.
- A header-named workspace requires an authenticated principal. A header with
  nobody behind it is a string from the internet. A *host*-named workspace
  still resolves anonymously, because a visitor has to reach the sign-in page.

## Rules `Identify` enforces before any lookup

1. **The host decides the surface**, always: marketing, platform (`sys.`),
   console (`app.`) or workspace.
2. **At most one workspace header.** Both set is a client bug, and guessing
   which was meant is how a client that sets them in two places reads the
   wrong tenant for a month.
3. **On a workspace host, a header must agree with the host.** A browser sends
   acme's cookie to `acme.fieldbubble.com` automatically; if a header could
   override the tenant from there, a page on acme could ask for globex with
   acme's credentials attached. A slug is compared immediately; a uuid cannot
   be compared without a lookup, so it travels as
   `Identifier.MustAgreeWith` and `Authorize` settles it — refusing a
   contradiction rather than resolving it in anyone's favour.
4. **Shape is validated before the database.** A malformed slug or uuid is
   refused up front, so nothing resembling SQL, a path or a cache-key
   separator ever reaches a cache key.

## Why `Source` is on the binding

So the cache can key each source separately. Conflating a host-resolved entry
with a header-resolved one lets a request on one host poison the other's
answer, which is a tenant leak rather than a cache bug.

## What this package does not do

It has no database, no cache and no HTTP client, and imports nothing outside
the standard library. The application supplies a `Registry`; `Lookup` and
`IsMember` are the only two questions asked of it. Caching those answers, and
invalidating them, belongs to the implementation.
