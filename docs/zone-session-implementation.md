# Zone-Scoped Session Implementation

This document describes how UAA implements per-zone session isolation for
path-based identity zones (`/z/{subdomain}/`). A single browser `JSESSIONID`
cookie holds separate, isolated session state for each zone the user visits.

## Problem

With subdomain-based zones (`tenant.login.example.com`), the browser naturally
separates cookies by domain. With path-based zones
(`login.example.com/z/tenant/`), all requests hit the same host and share a
single `JSESSIONID` cookie. Without additional work, logging in to one zone
would overwrite the security context of another, and logging out of any zone
would destroy all sessions.

## Design

The implementation follows **Idea 1** from
[session-persistence-zone-paths.md](session-persistence-zone-paths.md): a
single JSESSIONID cookie, a single underlying container/Spring Session, and
**server-side namespacing by context path**. Each zone's session attributes are
stored directly on the container session under prefixed keys
(`containerSessionAttributeName + ATTRIBUTE_KEY_DELIMITER + attributeName`), so
Spring Session sees every read/write immediately and there is no flush step or
timing dependency (e.g. avoids MySQL JDBC session visibility issues).

### Key classes

| Class | Role |
|---|---|
| `ZonePathContextRewritingFilter` | Rewrites `/uaa/z/tenant/login` so context path becomes `/uaa/z/tenant` and servlet path becomes `/login`. Also wraps the response to normalize cookie paths. |
| `SessionRepositoryFilter` (Spring Session) | Loads/saves the container session from the configured store (JDBC or in-memory). |
| `ZoneContextPathSessionFilter` | Wraps the request so `getSession()` returns a `ZonePathHttpSession` scoped to the current context path. Wraps the response to prevent premature JSESSIONID clearing. |
| `ZoneContextPathSessionRequestWrapper` | `HttpServletRequestWrapper` that intercepts `getSession()` and `changeSessionId()`. Caches a single `ZonePathHttpSession` per request (since each request has exactly one context path). If the cached sub-session has been invalidated, the cache is cleared so `getSession(true)` creates a fresh sub-session. |
| `ZoneContextPathSessionResponseWrapper` | `HttpServletResponseWrapper` that blocks `Set-Cookie` headers that would clear the JSESSIONID (since other zones may still be active). |
| `ZonePathHttpSession` | `HttpSession` view over one zone's attributes (each stored on the container as a prefixed key). Tracks per-sub-session `creationTime`, `lastAccessedTime`, and `isNew` independently of the container session (persisted as reserved prefixed attributes so they survive serialization). `invalidate()` removes only this zone's attributes and marks the sub-session as invalidated; it does not invalidate the container session. Uses `TimeService` for timestamps (injectable for testing). |

## Filter Chain Order

The order of the servlet filters is critical. Each filter wraps the request
and/or response, and the **last filter to wrap** is the wrapper that application
code (Spring Security, controllers) sees first via `request.getSession()`.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Incoming HTTP Request                       │
│                   GET /uaa/z/tenant/login HTTP/1.1                  │
│                   Cookie: JSESSIONID=abc123                         │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ① ZonePathContextRewritingFilter       (order: HIGHEST + 1)       │
│                                                                     │
│  • Rewrites request:                                                │
│      contextPath:  /uaa  →  /uaa/z/tenant                          │
│      servletPath:  /z/tenant/login  →  /login                      │
│  • Sets request attributes:                                         │
│      ZONE_SUBDOMAIN_FROM_PATH = "tenant"                            │
│      ZONE_ORIGINAL_CONTEXT_PATH = "/uaa"                            │
│  • Wraps response with CookiePathRewritingResponse:                 │
│      rewrites cookie path "/" → "/uaa" (the original context path)  │
│                                                                     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │  request: contextPath = /uaa/z/tenant
                                 │  response: cookie-path-rewriting wrapper
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ② SessionRepositoryFilter (Spring Session)   (order: HIGHEST + 2) │
│                                                                     │
│  • Loads the session from the configured store (JDBC / memory)      │
│    using the JSESSIONID cookie value.                               │
│  • Wraps the request so getSession() returns a Spring Session-      │
│    backed HttpSession (the "container session").                     │
│  • On response completion, persists dirty session attributes back   │
│    to the store.                                                    │
│  • Cookie path is forced to "/" by UaaSessionConfig, then the       │
│    CookiePathRewritingResponse (from step ①) rewrites it to the    │
│    original context path (e.g. /uaa).                               │
│                                                                     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │  request: getSession() → Spring Session
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ③ ZoneContextPathSessionFilter           (order: HIGHEST + 51)    │
│                                                                     │
│  • Wraps request with ZoneContextPathSessionRequestWrapper:         │
│      getSession() now returns a ZonePathHttpSession scoped to       │
│      the current contextPath ("/uaa/z/tenant").                     │
│  • Wraps response with ZoneContextPathSessionResponseWrapper:       │
│      blocks Set-Cookie headers that would clear JSESSIONID          │
│      (protects other zones' sessions).                              │
│  • On completion (finally block): if no zone attributes remain on   │
│    the container session, emits a Set-Cookie to clear the JSESSIONID.│
│    (No flush step — zone attributes are written directly to the     │
│    container session.)                                              │
│                                                                     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │  request: getSession() → ZonePathHttpSession
                                 │  response: blocks JSESSIONID clearing
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ④ Spring Security Filter Chain           (order: -100)            │
│                                                                     │
│  • Includes IdentityZoneResolvingFilter, authentication filters,    │
│    SecurityContextPersistenceFilter, etc.                           │
│  • Calls request.getSession() and gets the ZonePathHttpSession.     │
│  • Reads/writes SPRING_SECURITY_CONTEXT from/to the zone-scoped    │
│    sub-session — fully isolated from other zones.                   │
│                                                                     │
└────────────────────────────────┬────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     DispatcherServlet / Controllers                  │
└─────────────────────────────────────────────────────────────────────┘
```

### Order values (Spring Boot embedded)

| Filter | `Ordered` value | Configured in |
|---|---|---|
| `ZonePathContextRewritingFilter` | `HIGHEST_PRECEDENCE + 1` | `ZonePathContextRewritingFilterConfiguration` |
| `SessionRepositoryFilter` | `HIGHEST_PRECEDENCE + 2` | `UaaBootConfiguration.sessionRepositoryFilterRegistration()` |
| `ZoneContextPathSessionFilter` | `HIGHEST_PRECEDENCE + 51` | `ZonePathContextRewritingFilterConfiguration` |
| Spring Security (`springSecurityFilterChain`) | `-100` (Spring Boot default) | Spring Boot auto-configuration |

For traditional WAR deployments, the same order is established by registration
sequence in `UaaWebApplicationInitializer.onStartup()`.

## How the Container Session Stores Zone Attributes

The container session (the one managed by Spring Session or Tomcat) holds
**one attribute per zone attribute**, not one map per zone. The key for a zone
attribute is:

```
<containerSessionAttributeName><ATTRIBUTE_KEY_DELIMITER><attributeName>
```

where `containerSessionAttributeName` is
`org.cloudfoundry.identity.uaa.zone.ZonePathHttpSession.<contextPathKey>` (with
empty context path mapped to `"default"`), and `ATTRIBUTE_KEY_DELIMITER` is `"."`.
For example, `SPRING_SECURITY_CONTEXT` for zone `/uaa/z/tenant1` is stored under
`...ZonePathHttpSession./uaa/z/tenant1.SPRING_SECURITY_CONTEXT`. This way every
`ZonePathHttpSession.setAttribute()` calls `containerSession.setAttribute()` directly,
so Spring Session's dirty-tracking sees the change immediately and there is no
flush step or timing dependency (which avoids MySQL JDBC session visibility issues).

In addition to application attributes, each sub-session stores two reserved
metadata attributes under the same prefix:

- `__creationTime__` — the epoch millis when this sub-session was first created.
- `__lastAccessedTime__` — the epoch millis of the most recent `getSession()` access.

These are used by `getCreationTime()`, `getLastAccessedTime()`, and `isNew()` to
report per-sub-session values instead of delegating to the container session. On
construction, if `__creationTime__` is found on the container, the sub-session is
considered a reconnection (`isNew() == false`); otherwise it is new. When a
sub-session is invalidated, these metadata attributes are removed along with all
other prefixed attributes, so a subsequent `getSession(true)` creates a fresh
sub-session with new timestamps and `isNew() == true`. The reserved keys are
filtered out of `getAttributeNames()` so they are invisible to application code.

Requests to `/z/default/...` are **not** rejected. They are rewritten so that
the context path **includes** `/z/default` (e.g. `/uaa/z/default`), like any other
zone path. `ZoneContextPathSessionRequestWrapper` maps context path
`/uaa/z/default` to the same session key as the root (e.g. `/uaa`), so
`/profile` and `/z/default/profile` share the **same cookie and session**.

**Example** — a user logged in to the default zone and two path-based zones:

```
Container session id: abc123
  Attributes:
    ...ZonePathHttpSession.default.__creationTime__                  → 1710000000000
    ...ZonePathHttpSession.default.__lastAccessedTime__              → 1710000060000
    ...ZonePathHttpSession.default.SPRING_SECURITY_CONTEXT           → <admin auth>
    ...ZonePathHttpSession./uaa/z/tenant1.__creationTime__           → 1710000010000
    ...ZonePathHttpSession./uaa/z/tenant1.__lastAccessedTime__       → 1710000070000
    ...ZonePathHttpSession./uaa/z/tenant1.SPRING_SECURITY_CONTEXT    → <alice auth>
    ...ZonePathHttpSession./uaa/z/tenant2.__creationTime__           → 1710000020000
    ...ZonePathHttpSession./uaa/z/tenant2.__lastAccessedTime__       → 1710000080000
    ...ZonePathHttpSession./uaa/z/tenant2.SPRING_SECURITY_CONTEXT    → <bob auth>
```

## Session Lifecycle

### Login

1. Browser sends `POST /uaa/z/tenant/login.do` with `JSESSIONID=abc123`.
2. Filters ①–③ process the request; Spring Security authenticates the user.
3. Spring Security stores the `SecurityContext` via `session.setAttribute(...)`.
   Because `getSession()` returns a `ZonePathHttpSession`, the write goes
   directly to the container session under a prefixed key, so Spring Session
   marks it dirty immediately.
4. Filter ② commits the session to the store (JDBC or memory).
6. The `JSESSIONID` cookie (path `/uaa`) is shared across all zone paths.

### Subsequent request to a different zone

1. Browser sends `GET /uaa/z/other/profile` with the same `JSESSIONID=abc123`.
2. Filter ② loads the same container session from the store.
3. Filter ③ provides a `ZonePathHttpSession` for context path `/uaa/z/other`.
4. Spring Security reads `SPRING_SECURITY_CONTEXT` from the `/uaa/z/other`
   sub-session — this is a completely separate authentication from `/uaa/z/tenant`.

### Logout from one zone

1. Browser sends `GET /uaa/z/tenant/logout.do`.
2. Spring Security calls `session.invalidate()` on the `ZonePathHttpSession`.
3. `ZonePathHttpSession.invalidate()` removes all container session attributes
   whose key starts with this zone's prefix (including the reserved
   `__creationTime__` and `__lastAccessedTime__` metadata). The sub-session is
   marked as invalidated (`isInvalidated() == true`). **The container session
   itself is not invalidated.**
4. If code subsequently calls `request.getSession(true)` on the same request,
   `ZoneContextPathSessionRequestWrapper` detects that the cached sub-session is
   invalidated, clears its cache, and creates a fresh `ZonePathHttpSession`. The
   new sub-session has `isNew() == true` and fresh `creationTime`/`lastAccessedTime`
   timestamps, while other zones' sub-sessions are unaffected.
5. The `ZoneContextPathSessionResponseWrapper` blocks Spring Security's attempt
   to clear the `JSESSIONID` cookie (since other zones are still active).
6. In the filter's `finally` block, `maybeClearJSessionIdIfNoSubSessions` checks
   whether any container attributes with the zone prefix remain. If yes (other
   zones are still logged in), the cookie is left alone. If none remain, a
   `Set-Cookie` header is emitted to clear the `JSESSIONID`.

### Container session invalidation

If something invalidates the container session itself (not the sub-session),
all zones lose their sessions simultaneously. This mirrors the behavior of
subdomain-based zones where the session cookie would be deleted by the
browser. Application code should only invalidate the `ZonePathHttpSession`,
never the container session directly.

## Cookie Path

Spring Session's `DefaultCookieSerializer` is configured with a fixed cookie
path of `"/"` (`UaaSessionConfig.uaaCookieSerializer()`). This ensures the
browser always sends the `JSESSIONID` regardless of which zone path is being
accessed.

The `CookiePathRewritingResponse` (part of `ZonePathContextRewritingFilter`)
rewrites cookie paths from `"/"` to the original context path (e.g. `/uaa`) so
the cookie is properly scoped to the UAA deployment and not the entire domain.

## Spring Session Dirty-Tracking

Spring Session JDBC tracks which session attributes have been modified using a
delta map. Only attributes explicitly set via `containerSession.setAttribute()`
are considered dirty. `ZonePathHttpSession` stores each zone attribute directly
on the container session under a prefixed key (`containerSessionAttributeName +
ATTRIBUTE_KEY_DELIMITER + name`), so every `setAttribute` call is a
`containerSession.setAttribute()`. Spring Session therefore sees each change
immediately, and no flush step is needed. This also avoids timing/visibility
issues that can occur with MySQL and Spring Session JDBC when attributes are
batched (e.g. in a map) and written only at request end.

## Test Coverage

| Test class | Scope |
|---|---|
| `ZoneContextPathSessionTests` (server module, unit) | `ZonePathHttpSession`, `ZoneContextPathSessionRequestWrapper`, `ZoneContextPathSessionResponseWrapper`, `ZoneContextPathSessionFilter` — attribute isolation, invalidation semantics, direct container storage, cookie blocking, multi-zone lifecycle, per-sub-session `isNew`/`creationTime`/`lastAccessedTime` tracking, `isInvalidated` flag, wrapper cache clearing after invalidate |
| `ZonePathSessionMockMvcTests` (uaa module, MockMvc) | End-to-end login, profile access, and logout across multiple zones using `MockMvc` with the real filter chain. |
| `ZoneSessionPathsIT` (uaa module, integration) | Selenium-driven tests against a running UAA server. Logs in to default zone and two path-based zones, verifies profile isolation, verifies logout from one zone leaves others intact. |

## Configuration

| Property | Value | Effect |
|---|---|---|
| `servlet.session-store` | `database` or `memory` | Selects Spring Session JDBC or in-memory store. |
| `servlet.session-cookie.encode-base64` | `true`/`false` | Base64 encoding of the JSESSIONID value. |
| Cookie path | Fixed to `"/"` in `UaaSessionConfig` | Ensures one JSESSIONID is sent for all paths; rewritten to context path by `CookiePathRewritingResponse`. |
