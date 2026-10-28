package org.cloudfoundry.identity.uaa.oauth;

import lombok.Setter;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenRequestData;
import org.cloudfoundry.identity.uaa.util.TimeService;

import java.util.Date;
import java.time.Instant;

import static java.util.Optional.ofNullable;

public class TokenValidityResolver {
    public static final int DEFAULT_TO_GLOBAL_POLICY = -1;
    private final int globalTokenValiditySeconds;
    @Setter
    private TimeService timeService;
    private final ClientTokenValidity clientTokenValidity;

    public TokenValidityResolver(ClientTokenValidity clientTokenValidity,
            int globalTokenValiditySeconds,
            TimeService timeService) {
        this.clientTokenValidity = clientTokenValidity;
        this.globalTokenValiditySeconds = globalTokenValiditySeconds;
        this.timeService = timeService;
    }

    public Date resolve(String clientId) {
        return resolve(clientId, timeService.getCurrentTimeMillis());
    }

    public Date resolve(String clientId, long nowMillis) {
        Integer tokenValiditySeconds = ofNullable(
                clientTokenValidity.getValiditySeconds(clientId)
        ).orElse(
                clientTokenValidity.getZoneValiditySeconds()
        );

        if (tokenValiditySeconds == DEFAULT_TO_GLOBAL_POLICY) {
            tokenValiditySeconds = globalTokenValiditySeconds;
        }

        return Date.from(Instant.ofEpochMilli(nowMillis).plusSeconds(tokenValiditySeconds));
    }

    public Date resolve(String clientId, RefreshTokenRequestData requestData) {
        return resolve(clientId, requestData, timeService.getCurrentTimeMillis());
    }

    /**
     * Extension point for enterprise implementations that need to constrain refresh token
     * validity based on request context (e.g. a JIT session boundary carried in the assertion).
     * The default implementation ignores {@code requestData} and delegates to
     * {@link #resolve(String, long)} so iat and exp share one clock snapshot. Overrides that
     * compute a default expiry must use {@code nowMillis} via {@link #resolve(String, long)},
     * not an independent clock read, to preserve exp - iat == validity.
     *
     * @param clientId    the OAuth client identifier
     * @param requestData the refresh token request context; may be {@code null}
     * @param nowMillis   the issuance instant shared across all claims of this token
     * @return the effective expiration date
     */
    public Date resolve(String clientId, RefreshTokenRequestData requestData, long nowMillis) {
        return resolve(clientId, nowMillis);
    }
}
