# Identity Zone Subdomain Validation

Identity zone create (`POST /identity-zones`) and update (`PUT /identity-zones/{id}`) requests validate
`IdentityZone.subdomain`. Validation applies whether or not [zone path routing](zone-path-feature.md) is enabled,
because subdomains are used in both hostnames and `/z/{subdomain}/` URL paths.

## Accepted values

- Non-empty strings of at most 255 characters containing only ASCII letters, digits, underscores, or hyphens,
  such as `my-zone1` or `my_zone1`.
- Leading and trailing hyphens are rejected. Underscores, including leading and trailing ones, remain accepted
  for compatibility with existing zones. Prefer letters, digits, and hyphens for new DNS hostnames.
- Hyphenated UUID strings, such as `550e8400-e29b-41d4-a716-446655440000`, are valid subdomains.
- Values are stored and looked up in lowercase using `Locale.ROOT`, independently of the JVM's default locale.
  Hostname resolution and the legacy lowercase-subdomain migration use the same normalization.
  For example, `I-ZONE` is accepted and stored as ASCII `i-zone`, including under Turkish or Azerbaijani locales.
- Only the default UAA zone may have an empty subdomain.
- The name `default` is reserved, regardless of case, for the default zone's `/z/default/` path.

Dots, whitespace, URL delimiters such as `/`, `?`, and `#`, percent-encoded characters,
and non-ASCII characters are rejected. Values longer than 255 characters are rejected before reaching the database.

## Invalid requests and existing zones

Invalid subdomains return HTTP **422** with error `invalid_identity_zone` and an explanatory `error_description`.
Rejected creates do not persist a zone; rejected updates leave the stored zone unchanged.

Existing subdomains containing underscores remain valid and do not need to be changed before updating the zone.
Other invalid subdomains must be corrected before updating the zone. Such legacy zones can still be deleted.

### Locale-specific legacy mappings

Locale-independent normalization changes the behavior of uppercase requests that previously depended on the system
locale. For example, under Turkish a request for `I-ZONE` previously looked up `ı-zone`; it now looks up `i-zone`.
If both names exist, the uppercase request now targets the ASCII zone. Audit existing subdomains and configured
root hostnames before upgrading if they were created using locale-specific lowercasing.
Already-lowercase non-ASCII legacy values are not transliterated or automatically renamed. Their exact lowercase
names can still be looked up, but must be corrected to valid ASCII before API updates.
Changing the system locale after upgrading no longer changes ASCII subdomain normalization.

### Legacy lowercase-subdomain migration

These repairs apply only when Flyway runs `V2_7_3__StoreSubDomainAsLowerCase` on a database that has not yet
applied it. Upgrading an installation where that migration has already completed does not rerun it or
automatically repair legacy names.

The legacy lowercase-subdomain migration resolves case collisions by appending a hyphen and three lowercase ASCII
letters or digits, without introducing underscores or trailing hyphens.
An existing lowercase subdomain keeps its current zone owner, regardless of query order. If no lowercase owner
exists, the zone with the first ID in natural string order keeps the normalized name.
Existing underscore-containing bases are preserved during collision repair.
If legacy zones share the empty subdomain with the default UAA zone, the UAA zone keeps its empty subdomain
regardless of database query order; the other zones receive valid generated subdomains.
When a duplicate's legacy base is invalid, the renamed zone uses `zone` as a safe fallback base.
If needed, the base is shortened so the renamed subdomain stays within the 255-character limit
(251 base characters for the usual three-character suffix). Collisions are checked against the shortened value
before it is stored. After ten unsuccessful random suffix attempts, the migration uses an incrementing base-36
suffix to guarantee progress while preserving the same character and length constraints.
Legacy values whose Unicode lowercasing would exceed 255 characters are left unchanged for manual correction,
rather than blocking startup. Running the migration again does not rename already-repaired zones.
See the [Identity Zone Management APIs](UAA-APIs.rst) for authentication requirements and request examples.
