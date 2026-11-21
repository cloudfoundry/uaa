# Administrative token network policy

UAA can restrict issuance, refresh, and authenticated bearer-token use to operator-approved source networks,
without restricting ordinary tokens. The deployment-wide policy applies in every identity zone and cannot be
relaxed through tenant or client metadata. It is disabled by default.

## Configuration

```yaml
uaa:
  admin_token_network_policy:
    enabled: true
    allowed_cidrs:
      - 192.0.2.10/32
      - 2001:db8:1234::/48
    additional_protected_scopes:
      - clients.write
```

These are documentation addresses, not deployment recommendations. An enabled policy with an empty
allowlist denies all protected tokens. Invalid networks fail application startup, even when disabled.

Built-in protected scopes/authorities are `uaa.admin`, `cloud_controller.admin`,
`cloud_controller.admin_read_only`, `cloud_controller.global_auditor`, and `zones.<id>.admin`.
The zone matcher accepts any nonempty ID, including a literal wildcard. Additional scope names are exact
matches and extend, rather than replace, the built-in set. Ordinary `openid`, Cloud Controller read/write,
and unrelated scope names remain unaffected. This is not an exhaustive privilege-escalation boundary:
review client-management, SCIM, and other delegation privileges before enabling the policy.

Allowlist entries are numeric IPv4/IPv6 addresses or CIDRs with decimal prefix lengths (0–32 or 0–128).
Bare addresses match a single host; CIDRs mask host bits. Hostnames, abbreviated IPv4, netmask notation,
ports, brackets, whitespace, and IPv6 interface identifiers are rejected. IPv4-mapped IPv6 request
addresses match IPv4 entries; use IPv4 CIDRs rather than mapped-IPv6 CIDR notation.

## Issuance and use

UAA checks resolved scopes and client-only authorities before refresh-token creation, retains protection
for the broader `granted_scopes` of refresh tokens even when the requested access token is downscoped,
and rechecks final access/refresh claims before returning an access token. The common token-service hooks
cover password, client credentials, authorization code, implicit/hybrid, refresh, token exchange, and other
grants using these services, including the mTLS token endpoint.

A prohibited grant is rejected in full, not silently downscoped. Token endpoint denials return HTTP 403
with `error: access_denied` and `error_description: Administrative token source address is not allowed`.
Authorization endpoint flows use the existing OAuth authorization error handling.

Validated bearer authentication is checked before the success event, security-context publication, and
identity-zone switching on all resource security chains. Denied use returns the same HTTP 403 OAuth error.
The policy applies to previously issued JWTs and opaque tokens as well as new tokens. It does not treat
an introspection subject token as the caller's credential: ordinary service clients can still inspect
protected subject tokens. A protected bearer credential used to authenticate an introspection caller is
restricted normally.

Administrative JWT assertions and token-exchange subject tokens are also checked after signature,
issuer, and expiry validation, before authenticating the user, even if the output requests only ordinary
scopes. Opaque UAA exchange subjects are resolved through the existing revocable-token store. External
issuers/proxies remain responsible for their own token policies; a delegated proxy that transforms an
unvalidated input must enforce restrictions on that original input. Custom token-exchange authentication
managers must preserve equivalent checks; the default manager and independent subject verification do so.

## Trusted source addresses and rollout

The decision uses the **current servlet request's container-normalized remote address**, never a stored
login IP, an OAuth parameter, or the first forwarded-header value. A protected token with no established
request address is denied. Configure Tomcat's RemoteIpValve/Boot remote-IP handling to trust only actual
ingress proxies. In uaa-release, review `uaa.proxy_ips_regex`, `uaa.proxy.servers`, and router links;
the broad default private-network trust is not an administrative allowlist. A blank proxy regex restores
defaults and does not disable trust. Protect backend access and test forged forwarded headers through
the real ingress before enabling enforcement.

Cloud Controller validates tokens independently. Enable its corresponding `admin_token_network_policy`
with the same allowlist and protected additions, and explicitly configure its trusted ingress proxies.
Other resource servers need equivalent use-time enforcement; UAA alone cannot restrict offline JWT use.
This is a network allowlist, not cryptographic binding to the original issuance address.

Inventory administrator NAT/VPN egress and internal automation clients first. Configure both services,
verify allowed and denied issuance/use (including old tokens and refresh after moving networks), then
enable the policy. Do not allow a shared proxy/NAT merely to make tests pass. Keep a tested operator
configuration rollback path to avoid locking out administrators. Denials log a fixed message without
credentials or token contents; do not enable request dumps for production security auditing.
