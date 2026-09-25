package org.cloudfoundry.identity.uaa.spiffe;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Response body for {@code POST /jwt-svid/sign}. */
public record JwtSvidResponse(
        @JsonProperty("svid") String svid,
        @JsonProperty("spiffe_id") String spiffeId,
        @JsonProperty("expires_at") long expiresAt) {
}
