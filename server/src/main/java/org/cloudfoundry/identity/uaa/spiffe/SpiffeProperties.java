package org.cloudfoundry.identity.uaa.spiffe;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Binds {@code uaa.spiffe.*} from uaa.yml. Relaxed binding maps snake_case keys
 * (e.g. {@code uaa.spiffe.trust_domain}) to these record components.
 */
@ConfigurationProperties(prefix = "uaa.spiffe")
public record SpiffeProperties(
        String trustDomain,
        String instanceIdentityCa,
        Long jwtSvidTtlSeconds,
        Integer popFreshnessSeconds,
        Boolean popEnabled
) {
    public SpiffeProperties {
        if (jwtSvidTtlSeconds == null) {
            jwtSvidTtlSeconds = 3600L;
        }
        if (popFreshnessSeconds == null) {
            popFreshnessSeconds = 60;
        }
        if (popEnabled == null) {
            popEnabled = true;
        }
    }
}
