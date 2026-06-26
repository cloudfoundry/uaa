package org.cloudfoundry.identity.uaa.spiffe;

import com.fasterxml.jackson.annotation.JsonProperty;

/** Request body for {@code POST /jwt-svid/sign}. */
public record JwtSvidRequest(
        @JsonProperty("instance_certificate") String instanceCertificate,
        @JsonProperty("process_type") String processType,
        @JsonProperty("audience") String audience,
        @JsonProperty("timestamp") long timestamp,
        @JsonProperty("pop_signature") String popSignature) {
}
