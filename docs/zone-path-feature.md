# Zone Path-Based Multi-Tenancy

## 1. High-Level Overview

### Configuration

#### New configuration options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `zones.paths.enabled` | boolean | `false` | When `true`, enables path-based zone resolution. Requests to `/z/{subdomain}/*` are rewritten so the zone is taken from the path and the rest of the app sees a normal servlet path. When `false`, any request whose path starts with `/z/` receives **404 Not Found**. Non-zone-path requests are unaffected. |

YAML (under top-level `zones:`):

```yaml
zones:
  paths:
    enabled: true   # or false
```

- **Production default:** `uaa/src/main/resources/uaa.yml` sets `zones.paths.enabled: false`, so zone paths are off unless the deployer enables them.
- **Integration / test:** `scripts/boot/uaa.yml` and `uaa/src/test/resources/integration_test_properties.yml` set `zones.paths.enabled: true` so tests can exercise the feature.

#### Changed configuration options

None. No existing configuration options were changed by this feature.

---

### What was implemented

This changeset introduces **path-based identity zone resolution** as an alternative to the existing subdomain-based mechanism. Previously, UAA multi-tenancy worked exclusively through subdomains (e.g., `myzone.uaa.example.com`). With this feature, zones can also be addressed through a URL path prefix:

```
https://uaa.example.com/z/{subdomain}/login
```

There is one **hardcoded default**: when `{subdomain}` is `default`, the request is for the **default zone**. That path is equivalent to the same URL without the `/z/default` prefix. For example, `https://uaa.example.com/z/default/oauth/token` is the same as `https://uaa.example.com/oauth/token` (same zone, same session, same behavior).

This is useful in deployments where wildcard DNS or wildcard TLS certificates are not available or practical. A single hostname with a single certificate can now serve multiple identity zones.

### Features delivered

1. **URL path rewriting** — Requests to `/z/{subdomain}/*` are transparently rewritten so that downstream code (Spring Security matchers, controllers, Thymeleaf templates) sees a normal servlet path while the zone prefix is absorbed into the context path.

2. **Zone-scoped sessions** — A single `JSESSIONID` cookie (scoped to `/`) backs all zones. Each zone gets its own isolated sub-session view within the container session, allowing a user to be logged into multiple zones simultaneously without session interference.

3. **Cookie path normalization** — Cookies set by downstream filters/controllers are rewritten so that `JSESSIONID` and other cookies are scoped to the application's root context path, not to individual zone paths.

4. **Static resource link rewriting** — Thymeleaf `@{/resources/...}` and `@{/vendor/...}` links resolve against the original context path rather than the zone-prefixed context path, so static assets load correctly.

5. **Spring Session integration** — The session filter explicitly flushes sub-session attribute maps back to the container session on every request, working around Spring Session's dirty-tracking limitation with in-place map mutations.

6. **Default zone path** — The path prefix `/z/default/` is supported. The context path still includes `/z/default` (e.g. `getContextPath()` is `/uaa/z/default`), like any other zone path. What is unique is that the **session** (and thus the cookie) for `/z/default/` is the same as for the root path: `/profile` and `/z/default/profile` share the same JSESSIONID and session data (default zone). This allows clients to use a uniform URL pattern (always under `/z/{zone}/`) while still addressing the default zone.

7. **Comprehensive test coverage** — 38 zone-path-specific test classes (conditionally run when `zones.paths.enabled=true`), plus unit tests for the filter and session implementation (`ZonePathContextRewritingFilterTests`, `ZoneContextPathSessionTests`), and ZonePath variants of most existing MockMvc test suites.

---

## 2. Detailed Review of Modified Existing Production Code

### 2.1 `IdentityZoneResolvingFilter.java`

**What changed:** The monolithic `doFilterInternal` method was refactored into four private methods and extended with path-based zone resolution.

**Why:** The filter previously only resolved zones from the hostname subdomain. It now has a two-source resolution strategy:

- **`resolveEffectiveSubdomain()`** — Checks for a `ZONE_SUBDOMAIN_FROM_PATH` request attribute (set by `ZonePathContextRewritingFilter`). If present, uses it as the zone subdomain. If absent, falls back to hostname-based resolution. If **both** a path-based zone and a hostname-based zone are present, it sends a `400 Bad Request` to prevent ambiguity. This filter does **not** attempt to parse the context path — zone-from-path resolution is entirely the responsibility of `ZonePathContextRewritingFilter`, which communicates its result via the request attribute.

- **`getSubdomain()` → `getSubdomainFromHost()`** — Renamed for clarity; behavior unchanged.

The refactoring into `resolveZoneBySubdomain()`, `handleZoneNotFound()`, and `doFilterWithZone()` is a readability improvement that also makes each responsibility independently testable.

**Default zone path (`/z/default/`):** `ZonePathContextRewritingFilter` does **not** set `ZONE_SUBDOMAIN_FROM_PATH` for `/z/default/` requests. This means `resolveEffectiveSubdomain()` sees `null` for the path attribute and falls through to hostname-based resolution, which naturally resolves to the default zone. No special-case "default" handling is needed in this filter.

### 2.2 `OpenIdConnectEndpoints.java`

**What changed:** The `getServerContextPath()` method was rewritten from a `requestURL` substring approach to a manual `scheme + host + port + contextPath` construction.

**Why:** The old implementation computed the server base URL by stripping the servlet path from the request URL. With zone path rewriting, the request URL contains the zone prefix in the context path (e.g., `/uaa/z/myzone`), and the old arithmetic of `requestURL.length() - servletPath.length()` could produce incorrect results. Building the URL from individual components (`getScheme()`, `getServerName()`, `getServerPort()`, `getContextPath()`) is more robust and works correctly whether the context path includes a zone prefix or not.

### 2.3 `InvitationsController.java`

**What changed:** A redirect from `"redirect:accept"` (relative) to `"redirect:/invitations/accept"` (absolute within the application).

**Why:** Relative redirects like `redirect:accept` resolve against the current request path. With zone path rewriting, the context path changes (e.g., from `/uaa` to `/uaa/z/myzone`), which can cause relative redirects to resolve incorrectly. Using an application-absolute path (`/invitations/accept`) ensures the redirect resolves correctly regardless of how the context path was rewritten. Spring MVC prepends the context path automatically, producing the correct final URL.

### 2.4 `ThymeleafConfig.java`

**What changed:** Added `springTemplateEngine.setLinkBuilder(new ZoneAwareStaticResourceLinkBuilder())`.

**Why:** Thymeleaf's `@{...}` link expressions prepend the context path. When a request is zone-rewritten, the context path becomes `/uaa/z/myzone`, so `@{/resources/style.css}` would resolve to `/uaa/z/myzone/resources/style.css` — a path that doesn't exist. The custom link builder detects URLs starting with `/vendor/` or `/resources/` and substitutes the original (pre-rewrite) context path so static assets always load from the correct location.

### 2.5 `UaaUrlUtils.java`

**What changed:** Added an early-return in `getSubdomainUri()` and a new `isZoneInRequestPath()` helper.

**Why:** `getSubdomainUri()` is used throughout UAA to build URLs that incorporate the current zone's subdomain into the hostname. When the zone is already encoded in the URL path (context path contains `/z/`), prepending the subdomain to the hostname would produce broken URLs like `myzone.uaa.example.com/z/myzone/...`. The new guard detects path-based zone resolution from the current request's context path and skips the subdomain-in-host logic.

### 2.6 `UaaSessionConfig.java`

**What changed:** Added `cookieSerializer.setCookiePath("/")`.

**Why:** Without this, Spring Session's `DefaultCookieSerializer` uses the request's context path to scope the `JSESSIONID` cookie. For zone-path requests, this means each zone would get its own cookie path (e.g., `Path=/uaa/z/zone1`), preventing the single-cookie multi-zone session design from working. Forcing `Path=/` ensures the browser sends the same `JSESSIONID` for all zone paths, and the `CookiePathRewritingResponse` in `ZonePathContextRewritingFilter` then rewrites it to the application context path (e.g., `/uaa`) for proper scoping.

### 2.7 `UaaBootConfiguration.java`

**What changed:** Replaced `DelegatingFilterProxyRegistrationBean` for `springSessionRepositoryFilter` with a standard `FilterRegistrationBean<Filter>` that wraps the auto-configured filter bean via `@Qualifier("springSessionRepositoryFilter")`, and explicitly sets its order to `Ordered.HIGHEST_PRECEDENCE + 2`.

**Why:** Two problems were solved:

1. **Filter ordering** — The zone path feature requires a specific filter chain order: rewriting (+1) → Spring Session (+2) → zone session (+51) → Spring Security. The old `DelegatingFilterProxyRegistrationBean` did not control order.

2. **Duplicate registration** — Spring Boot's `SessionAutoConfiguration` already registers a `FilterRegistrationBean` for `springSessionRepositoryFilter`. Adding a second `DelegatingFilterProxyRegistrationBean` caused `IllegalStateException: Failed to register filter`. The new approach wraps the same bean with a different `FilterRegistrationBean`, letting Spring Boot's auto-configuration handle the actual filter creation while this bean controls the order.

### 2.8 `UaaWebApplicationInitializer.java`

**What changed:** Added registration of `ZonePathContextRewritingFilter` and `ZoneContextPathSessionFilter` as `DelegatingFilterProxy` entries before and after `springSessionRepositoryFilter` respectively.

**Why:** This file configures the filter chain for traditional WAR deployments (as opposed to embedded Spring Boot). The registration order in `onStartup()` determines the filter execution order: rewriting → Spring Session → zone session → Spring Security. Both new filters are registered with `DelegatingFilterProxy` so they are looked up from the Spring context at runtime, consistent with the existing pattern for `springSessionRepositoryFilter` and `springSecurityFilterChain`.

---

## 3. New Production Classes

### 3.1 `ZonePathContextRewritingFilter` — The URL Rewriter

The outermost filter in the chain (`Ordered.HIGHEST_PRECEDENCE + 1`). For requests matching `/z/{subdomain}/...`:

- **Rewrites the request** by wrapping it in `ZonePathRewrittenRequest` (a private `HttpServletRequestWrapper`) that moves `/z/{subdomain}` from the servlet path into the context path. Downstream code sees `getContextPath()` = `/uaa/z/myzone` and `getServletPath()` = `/login`.
- **Sets request attributes** `ZONE_SUBDOMAIN_FROM_PATH` (the subdomain string) and `ZONE_ORIGINAL_CONTEXT_PATH` (the pre-rewrite context path like `/uaa`), consumed by `IdentityZoneResolvingFilter` and `ZoneAwareStaticResourceLinkBuilder`.
- **Wraps the response** in `CookiePathRewritingResponse` which intercepts `addCookie()`, `addHeader("Set-Cookie", ...)`, and `setHeader("Set-Cookie", ...)` to rewrite cookie paths from `/` back to the original context path (e.g., `/uaa`).
- **Default zone path:** For the subdomain `"default"`, rewrites so the context path **includes** `/z/default` (e.g. `/uaa/z/default`), like any other zone path. Does **not** set `ZONE_SUBDOMAIN_FROM_PATH` so the default zone is resolved. `ZoneContextPathSessionRequestWrapper` maps this context path to the same session key as the root, so `/profile` and `/z/default/profile` share the same cookie/session. See "Default zone path" below.
- **Passes through** non-zone requests unchanged (but still wraps the response for cookie path normalization when a context path is present).

#### Default zone path

The path prefix `/z/default/` is allowed. The context path **includes** `/z/default` (like any other `/z/{subdomain}/`), so downstream sees e.g. `getContextPath() == "/uaa/z/default"` and `getServletPath() == "/login"`. Examples:

- No context path: `/z/default/login` → context path `/z/default`, servlet path `/login`.
- With context path `/uaa`: `/uaa/z/default/login` → context path `/uaa/z/default`, servlet path `/login`.

What is unique: the **session** (and cookie) for `/z/default/` is the same as for the root path. `ZoneContextPathSessionRequestWrapper` maps context path `/uaa/z/default` (or `/z/default`) to the same session key as `/uaa` (or `""`), so a user logged in at `/uaa/login` is also logged in at `/uaa/z/default/profile`, and vice versa.

### 3.2 `ZonePathContextRewritingFilterConfiguration` — Spring Configuration

A `@Configuration` class that registers both `ZonePathContextRewritingFilter` (order +1) and `ZoneContextPathSessionFilter` (order +51) as `FilterRegistrationBean`s. Centralizes the filter ordering constants.

### 3.3 `ZoneContextPathSessionFilter` — The Session Namespace Filter

Runs after `SessionRepositoryFilter` (`Ordered.HIGHEST_PRECEDENCE + 51`). Wraps the request and response in `ZoneContextPathSessionRequestWrapper` and `ZoneContextPathSessionResponseWrapper`. In its `finally` block:

1. **Flushes the sub-session** — If the request's single cached `ZonePathHttpSession` was modified (dirty), re-sets its attribute map on the container session via `containerSession.setAttribute(name, value)`. This forces Spring Session's dirty-tracking to detect in-place `ConcurrentHashMap` mutations and persist them.
2. **Clears JSESSIONID if empty** — If no sub-session attribute maps remain on the container session (all zones have been logged out), sends a `Set-Cookie: JSESSIONID=; Max-Age=0` header to clean up the cookie.

### 3.4 `ZoneContextPathSessionRequestWrapper` — The Session View Provider

An `HttpServletRequestWrapper` that intercepts `getSession()` and `getSession(boolean)`. Instead of returning the raw container session, it returns a `ZonePathHttpSession` scoped to the current context path. Since a single request always has exactly one context path, at most one `ZonePathHttpSession` is created per wrapper instance (cached in a single field). The container session holds one attribute per context path (e.g., `...ZonePathHttpSession./uaa/z/myzone`), with the value being a `ConcurrentHashMap<String, Object>` of that zone's session attributes.

Also overrides `changeSessionId()` to snapshot and restore sub-session attributes when the container session is rotated (e.g., during Spring Security's session fixation prevention).

### 3.5 `ZoneContextPathSessionResponseWrapper` — The Cookie Guard

An `HttpServletResponseWrapper` that intercepts `addCookie()`, `addHeader()`, and `setHeader()` to suppress any attempt to clear the `JSESSIONID` cookie (max-age=0 or empty value). This is critical because individual zone logouts would otherwise clear the shared cookie, invalidating sessions for all other zones. The `ZoneContextPathSessionFilter` handles JSESSIONID cleanup at the end of the request if all sub-sessions are gone.

### 3.6 `ZonePathHttpSession` — The Sub-Session View

Implements `HttpSession` backed by a `Map<String, Object>` stored as an attribute on the container session. Key design decisions:

- **Attribute operations** (`getAttribute`, `setAttribute`, `removeAttribute`, `getAttributeNames`) operate on the sub-session map only.
- **`getId()`** returns `containerSession.getId() + "-" + suffix` where the suffix is derived from the context path (e.g., `"z-myzone"`) or `"default"` for the root.
- **`invalidate()`** clears the sub-session map and removes it from the container session, but does **not** invalidate the container session itself.
- **Delegation** — `getCreationTime()`, `getLastAccessedTime()`, `getMaxInactiveInterval()`, `setMaxInactiveInterval()`, `isNew()`, `getServletContext()` all delegate to the container session.

### 3.7 `ZoneAwareStaticResourceLinkBuilder` — Thymeleaf Link Builder

Extends `StandardLinkBuilder` and overrides `computeContextPath()`. For URLs starting with `/vendor/` or `/resources/`, returns the value of `ZONE_ORIGINAL_CONTEXT_PATH` instead of the rewritten context path. This ensures static asset URLs are not prefixed with the zone path.

---

## 3.8 Feature Flag: `zones.paths.enabled`

The entire zone-path feature can be enabled or disabled at runtime through the `zones.paths.enabled` property.

### How it works

`ZonePathContextRewritingFilter` accepts a `boolean zonePathsEnabled` constructor parameter. When the flag is `false`, any request whose path starts with `/z/` receives a **404 Not Found** response immediately — the filter does not rewrite the request or invoke the rest of the filter chain. Non-zone-path requests are unaffected and pass through normally regardless of the flag.

`ZonePathContextRewritingFilterConfiguration` reads the property via `@Value("${zones.paths.enabled:false}")` and passes it to the filter constructor. The **default is `false`** so that zone paths are off unless explicitly enabled.

### Configuration

| File | Value | Purpose |
|---|---|---|
| `uaa/src/main/resources/uaa.yml` | `false` | Default for production — zone paths are **off** unless explicitly enabled by the deployer. |
| `scripts/boot/uaa.yml` | `true` | Development/integration test server — zone paths are **on** so that integration tests exercise the feature. |
| `uaa/src/test/resources/integration_test_properties.yml` | `true` | Unit test properties — zone paths are **on** so that `@DefaultTestContext` MockMvc tests exercise zone-path filters. |

YAML syntax in all three files:

```yaml
zones:
  paths:
    enabled: true   # or false
```

### Gradle / command-line override

The flag is forwarded from Gradle's `-D` arguments to the test JVM and the `bootWarRun` task via `systemProperty("zones.paths.enabled", ...)`. This allows running the full test suite in either mode:

```bash
# All tests (zone-path tests included — the default)
./gradlew clean test
./gradlew integrationTest

# Zone-path tests skipped
./gradlew -Dzones.paths.enabled=false clean test
./gradlew -Dzones.paths.enabled=false integrationTest
```

### Test skipping mechanism

All zone-path-specific test classes (37 unit/MockMvc test classes + `ZoneSessionPathsIT` = 38 total) are annotated with `@EnabledIfZonePathsEnabled`, a meta-annotation backed by JUnit 5's `@EnabledIfSystemProperty(named = "zones.paths.enabled", matches = "true")`. When the system property is `false`, these tests are reported as **skipped** rather than failing. (Unit tests for the filter and session implementation itself — `ZonePathContextRewritingFilterTests`, `ZoneContextPathSessionTests` — run in all modes and are not annotated.)

---

## 4. Modified Existing Test Code

### 4.1 `DefaultTestContext.java` — MockMvc filter chain setup

**What changed:** The `mockMvc` bean now injects and registers `ZonePathContextRewritingFilter` and `ZoneContextPathSessionFilter` alongside `springSecurityFilterChain`.

**Why:** MockMvc tests need the same filter chain as the real server. Without these filters, MockMvc tests would not exercise zone path rewriting or session namespacing, and the `ZonePathHttpSession` sub-session mechanism would not be active. This is the single most impactful change to existing tests — it means *all* existing `@DefaultTestContext` MockMvc tests now run with zone-path filters in the chain.

### 4.2 `MockMvcUtils.java` — Test utility additions

**What changed:** Added `getZoneSession()` helper methods (three overloads) that return a `ZonePathHttpSession` view for a given container session and context path.

**Why:** With `ZoneContextPathSessionFilter` now in the MockMvc filter chain, all session attributes are stored inside the sub-session map, not directly on the `MockHttpSession`. Existing tests that read/write session attributes (e.g., `session.getAttribute(SPRING_SECURITY_CONTEXT_KEY)`) need to go through `getZoneSession()` to access the correct sub-session namespace. The `getSavedRequestSession()` factory was also updated to store saved requests in the sub-session.

### 4.3 Pattern: Session attribute access in existing tests

The following existing test classes all received the same type of change — replacing direct session attribute access with `MockMvcUtils.getZoneSession(session).getAttribute(...)` or `.setAttribute(...)`:

| Test Class | # of Changes | What was changed |
|---|---|---|
| `AccountsControllerMockMvcTests` | 7 | `SecurityContext` reads and `SavedRequest` reads |
| `LoginMockMvcTests` | 12 | `SavedRequest` writes, `SecurityContext` reads/writes, redirect URL assertion |
| `PasscodeMockMvcTests` | 6 | `SecurityContext` writes into session |
| `ForcePasswordChangeControllerMockMvcTest` | 8 | `SecurityContext` reads and `isPasswordChangeRequired` checks |
| `TokenMvcMockTests` | 7 | `AuthorizationRequest` writes and `SavedRequest` reads |
| `ApprovalsMockMvcTests` | 8 | `AuthorizationRequest` attribute assertions |
| `PasswordChangeEndpointMockMvcTests` | 5 | `SecurityContext` reads, removed stale `isInvalid()` assertions |
| `InvitationsServiceMockMvcTests` | 2 | `SecurityContext` reads |
| `ResetPasswordControllerMockMvcTests` | 1 | `SavedRequest` write |
| `AbstractLdapMockMvcTest` | 2 | `SecurityContext` reads |
| `UaaAuthorizationEndpointMockMvcTest` | 1 | `SecurityContext` write |
| `DisableUserManagementSecurityFilterMockMvcTest` | 1 | Method rename only |

All changes follow the same mechanical pattern: `session.getAttribute(X)` → `MockMvcUtils.getZoneSession(session).getAttribute(X)` and `session.setAttribute(X, Y)` → `MockMvcUtils.getZoneSession(session).setAttribute(X, Y)`.

### 4.4 `InvitationsControllerTest.java`

**What changed:** Updated redirect assertions from `"redirect:accept"` to `"redirect:/invitations/accept"`, and adjusted a follow-redirect helper to handle absolute paths.

**Why:** This mirrors the production change in `InvitationsController.java` where the relative redirect was changed to an absolute path.

### 4.5 `LoginMockMvcTests.java` — Specific behavioral changes

Beyond the session access pattern, two notable changes:

1. **`test_idp_discovery_with_SessionSavedRequest`** — Added `.contextPath("/uaa")` to the authorize request and updated the expected redirect URL to include `/uaa`. This ensures the test correctly exercises a context-path deployment, which is now required with the cookie path rewriting in place.

2. **Redirect assertion** — `redirectedUrlPattern("accept?error_message_code=form_error&code=*")` was updated to `redirectedUrlPattern("/invitations/accept?error_message_code=form_error&code=*")` to match the production `InvitationsController` change.

### 4.6 `PasswordChangeEndpointMockMvcTests.java`

**What changed:** Beyond the session access pattern, the test `changePassword_Returns302_WithRedirect_AndInvalidates_OldSession` was updated to no longer assert `afterLoginSession.isInvalid()` or `afterLoginSession != afterPasswordChange`. Instead, it validates that the `SecurityContext` is present in the post-change session and that the authentication timestamp is >= the pre-change timestamp.

**Why:** With sub-sessions, password change may not invalidate the `MockHttpSession` object itself (it clears the sub-session), so `isInvalid()` on the container session is no longer the right assertion. The semantic check (authenticated context exists with valid timestamp) is more appropriate and works with both session models.

---

## Summary

This is a large but well-structured changeset. The production code additions (~1,000 lines across 7 new classes + 5 modified files) are focused and cohesive, implementing a clear filter-chain-based architecture. The overwhelming majority of the diff (~29,400 lines) is test code: 38 zone-path-specific test classes (plus filter/session unit tests) that mirror existing test suites under zone-path mode, plus mechanical adjustments to 12 existing test classes to account for session attribute namespacing.

The modifications to existing production code are minimal and surgical — no behavioral changes for subdomain-based zone resolution, no changes to database schemas, and no API contract changes. The existing test adjustments are all a direct consequence of the `ZoneContextPathSessionFilter` being added to the MockMvc filter chain, which namespaces all session attributes under a sub-session map.
