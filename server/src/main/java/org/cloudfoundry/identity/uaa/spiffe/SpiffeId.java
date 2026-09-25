package org.cloudfoundry.identity.uaa.spiffe;

import java.util.regex.Pattern;

/** Pure formatter for CF workload SPIFFE IDs, enforcing SPIFFE-ID syntax on every segment. */
public final class SpiffeId {

    /**
     * SPIFFE-ID spec: "Individual path segments MUST contain only letters, numbers, dots, dashes,
     * and underscores ([a-zA-Z0-9.-_])".
     *
     * <p>Every segment interpolated here is attacker-influenced -- three come from certificate OU
     * attributes and one from the request body -- and they all land both in the path relying
     * parties authorize on and in the newline-delimited proof-of-possession message. An
     * unvalidated {@code /} lets one workload's identifier masquerade as a longer path belonging
     * to another, and an unvalidated newline makes the signed message ambiguous.
     */
    private static final Pattern PATH_SEGMENT = Pattern.compile("[a-zA-Z0-9._-]+");

    /** SPIFFE-ID spec: the host part MUST be non-empty, lowercase, and only {@code [a-z0-9.-_]}. */
    private static final Pattern TRUST_DOMAIN = Pattern.compile("[a-z0-9._-]+");

    /** SPIFFE-ID spec: "SPIFFE implementations MUST support SPIFFE URIs up to 2048 bytes in length". */
    private static final int MAX_LENGTH = 2048;

    /** RFC 3986 caps the host component of a URI at 255 bytes. */
    private static final int MAX_TRUST_DOMAIN_LENGTH = 255;

    private SpiffeId() {
    }

    public static String format(String trustDomain, CfInstanceIdentity identity, String processType) {
        String spiffeId = "spiffe://" + requireTrustDomain(trustDomain)
                + "/cf/org/" + requireSegment(identity.orgId(), "org")
                + "/space/" + requireSegment(identity.spaceId(), "space")
                + "/app/" + requireSegment(identity.appId(), "app")
                + "/process/" + requireSegment(processType, "process");
        if (spiffeId.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("SPIFFE ID exceeds the " + MAX_LENGTH + " byte maximum");
        }
        return spiffeId;
    }

    /**
     * Validates an operator-supplied trust domain. Called at startup so that a missing value is a
     * boot failure rather than a foundation's worth of {@code spiffe://null/cf/org/...} identities.
     *
     * @throws IllegalArgumentException if the trust domain is absent or not SPIFFE-conformant
     */
    public static String requireTrustDomain(String trustDomain) {
        if (trustDomain == null || trustDomain.isEmpty()) {
            throw new IllegalArgumentException("uaa.spiffe.trust-domain must be set");
        }
        if (trustDomain.length() > MAX_TRUST_DOMAIN_LENGTH || !TRUST_DOMAIN.matcher(trustDomain).matches()) {
            throw new IllegalArgumentException("uaa.spiffe.trust-domain must be at most "
                    + MAX_TRUST_DOMAIN_LENGTH + " characters from [a-z0-9.-_], all lowercase, but was '"
                    + trustDomain + "'");
        }
        return trustDomain;
    }

    /** Deliberately does not echo the offending value, which comes from a client certificate. */
    private static String requireSegment(String value, String name) {
        if (value == null || !PATH_SEGMENT.matcher(value).matches()
                || ".".equals(value) || "..".equals(value)) {
            throw new IllegalArgumentException("SPIFFE ID " + name
                    + " segment must consist of [a-zA-Z0-9.-_] and must not be '.' or '..'");
        }
        return value;
    }
}
