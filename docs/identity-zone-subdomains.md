# Identity Zone Subdomain Validation

Identity zone create (`POST /identity-zones`) and update (`PUT /identity-zones/{id}`) requests validate
`IdentityZone.subdomain`. Validation applies whether or not [zone path routing](zone-path-feature.md) is enabled,
because subdomains are used in both hostnames and `/z/{subdomain}/` URL paths.

## Accepted values

- Non-empty strings of at most 255 characters containing only ASCII letters, digits, or hyphens, such as `my-zone1`.
- The first and last characters must be letters or digits.
- Hyphenated UUID strings, such as `550e8400-e29b-41d4-a716-446655440000`, are valid subdomains.
- Values are stored and looked up in lowercase, independently of the JVM's default locale.
  The legacy lowercase-subdomain migration also uses locale-independent normalization, including duplicate detection.
- Only the default UAA zone may have an empty subdomain.
- The name `default` is reserved, regardless of case, for the default zone's `/z/default/` path.

Dots, underscores, whitespace, URL delimiters such as `/`, `?`, and `#`, percent-encoded characters,
and non-ASCII characters are rejected. Values longer than 255 characters are rejected before reaching the database.

## Invalid requests and existing zones

Invalid subdomains return HTTP **422** with error `invalid_identity_zone` and an explanatory `error_description`.
Rejected creates do not persist a zone; rejected updates leave the stored zone unchanged.

Existing invalid subdomains must be corrected before updating the zone. Such legacy zones can still be deleted.
The legacy lowercase-subdomain migration resolves case collisions by appending a hyphen and three lowercase ASCII
letters or digits, without introducing underscores or trailing hyphens.
When a duplicate's legacy base is invalid, the renamed zone uses `zone` as a safe fallback base.
If needed, the base is shortened so the renamed subdomain stays within the 255-character limit
(251 base characters for the usual three-character suffix). Collisions are checked against the shortened value
before it is stored. After ten unsuccessful random suffix attempts, the migration uses an incrementing base-36
suffix to guarantee progress while preserving the same character and length constraints.
Legacy values whose Unicode lowercasing would exceed 255 characters are left unchanged for manual correction,
rather than blocking startup. Running the migration again does not rename already-repaired zones.
See the [Identity Zone Management APIs](UAA-APIs.rst) for authentication requirements and request examples.
