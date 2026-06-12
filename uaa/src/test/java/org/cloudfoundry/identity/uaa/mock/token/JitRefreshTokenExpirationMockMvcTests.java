package org.cloudfoundry.identity.uaa.mock.token;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.ClientTokenValidity;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenEnhancer;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenRequestData;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;

import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXTERNAL_ATTR;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Demonstrates the pluggable {@link TokenValidityResolver} extension point.
 *
 * <p>The two inner beans are an example what a proprietary module could provide:
 * <ol>
 *   <li>A {@link UaaTokenEnhancer} that deposits a {@code exampleRefreshTokenExpiration} claim
 *       (read in production from {@code UaaAuthentication#getIdpIdToken()}) into the
 *       token's external attributes map.</li>
 *   <li>A {@link TokenValidityResolver} subclass that reads that claim and clamps the
 *       refresh token's TTL to {@code min(requestedExpiration, defaultExpiration)}.</li>
 * </ol>
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(JitRefreshTokenExpirationMockMvcTests.JitConfiguration.class)
@DefaultTestContext
public class JitRefreshTokenExpirationMockMvcTests extends JwtBearerGrantMockMvcTests {

    /**
     * Controls the {@code exampleRefreshTokenExpiration} claim injected by the test enhancer.
     * Set to a specific {@link Instant} before each grant call; set to {@code null} to
     * simulate an absent claim (fallback to default TTL).
     */
    static final AtomicReference<Instant> requestedExpiration = new AtomicReference<>();

    @Autowired
    private RevocableTokenProvisioning revocableTokenProvisioning;

    // ---------------------------------------------------------------------------
    // Inner Spring configuration — simulates the two proprietary extension beans
    // ---------------------------------------------------------------------------

    static class JitConfiguration {

        /**
         * Simulates an extension to {@link UaaTokenEnhancer} that reads
         * {@code exampleRefreshTokenExpiration} from the incoming JWT assertion and deposits it
         * as a top-level entry in the token's external-attributes map.
         *
         * <p>In this example the value would be extracted from
         * {@code ((UaaAuthentication) auth.getUserAuthentication()).getIdpIdToken()}.
         * Here we use the static {@link #requestedExpiration} so each test can control it.
         */
        @Bean
        UaaTokenEnhancer uaaTokenEnhancer() {
            return new UaaTokenEnhancer() {
                @Override
                public Map<String, String> getExternalAttributes(OAuth2Authentication authentication) {
                    return Map.of();
                }

                @Override
                public Map<String, Object> enhance(Map<String, Object> claims, OAuth2Authentication authentication) {
                    Map<String, Object> result = new HashMap<>();
                    result.put(EXTERNAL_ATTR, getExternalAttributes(authentication));
                    Instant exp = requestedExpiration.get();
                    if (exp != null) {
                        result.put("exampleRefreshTokenExpiration", exp.toString());
                    }
                    return result;
                }
            };
        }

        /**
         * Simulates an extension {@link TokenValidityResolver} subclass that applies
         * session-bound clamping: the effective expiry is the earlier of the requested
         * {@code exampleRefreshTokenExpiration} claim and the zone/client/global default.
         *
         * <p>Registered under the well-known qualifier so the
         * {@code @ConditionalOnMissingBean} on the OSS default skips creating its own.
         */
        @Bean("refreshTokenValidityResolver")
        TokenValidityResolver refreshTokenValidityResolver(
                @Qualifier("clientRefreshTokenValidity") ClientTokenValidity clientRefreshTokenValidity,
                @Value("${jwt.token.policy.global.refreshTokenValiditySeconds:2592000}") int globalTokenValiditySeconds,
                TimeService timeService
        ) {
            return new TokenValidityResolver(clientRefreshTokenValidity, globalTokenValiditySeconds, timeService) {
                @Override
                public Date resolve(String clientId, RefreshTokenRequestData requestData) {
                    Date defaultExpiration = resolve(clientId);
                    if (requestData == null || requestData.externalAttributes == null) {
                        return defaultExpiration;
                    }
                    Object claim = requestData.externalAttributes.get("exampleRefreshTokenExpiration");
                    if (claim == null) {
                        return defaultExpiration;
                    }
                    Instant requested = Instant.parse(claim.toString());
                    return requested.isBefore(defaultExpiration.toInstant())
                            ? Date.from(requested)
                            : defaultExpiration;
                }
            };
        }
    }

    // ---------------------------------------------------------------------------
    // Test scenarios
    // ---------------------------------------------------------------------------

    @Test
    void refreshTokenExpiresAtAssertionTime_whenClaimIsBeforeDefault() throws Exception {
        Instant expiresAt = Instant.now().plusSeconds(60);
        requestedExpiration.set(expiresAt);

        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        String assertion = getUaaIdToken(originZone.getIdentityZone(), originClient, originUser);

        String refreshToken = performJwtBearerGrantForRefreshToken(defaultZone, assertion);

        long expClaim = getRefreshTokenExpClaim(refreshToken);
        assertThat(expClaim).isCloseTo(expiresAt.getEpochSecond(), within(5L));
    }

    @Test
    void refreshTokenExpiresAtDefault_whenClaimExceedsDefault() throws Exception {
        // Far future — must be clamped to the zone/global refreshTokenValidity (default: 30 days)
        requestedExpiration.set(Instant.now().plusSeconds(Integer.MAX_VALUE));

        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        String assertion = getUaaIdToken(originZone.getIdentityZone(), originClient, originUser);

        String refreshToken = performJwtBearerGrantForRefreshToken(defaultZone, assertion);

        long expectedDefault = Instant.now().plusSeconds(2592000).getEpochSecond();
        long expClaim = getRefreshTokenExpClaim(refreshToken);
        assertThat(expClaim).isCloseTo(expectedDefault, within(10L));
    }

    @Test
    void refreshTokenExpiresAtDefault_whenClaimAbsent() throws Exception {
        requestedExpiration.set(null);

        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        String assertion = getUaaIdToken(originZone.getIdentityZone(), originClient, originUser);

        String refreshToken = performJwtBearerGrantForRefreshToken(defaultZone, assertion);

        long expectedDefault = Instant.now().plusSeconds(2592000).getEpochSecond();
        long expClaim = getRefreshTokenExpClaim(refreshToken);
        assertThat(expClaim).isCloseTo(expectedDefault, within(10L));
    }

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    private String performJwtBearerGrantForRefreshToken(IdentityZone zone, String assertion) throws Exception {
        ClientDetails client = createJwtBearerClient(zone);
        String json = mockMvc.perform(
                        post("/oauth/token")
                                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                                .param("client_id", client.getClientId())
                                .param("client_secret", client.getClientSecret())
                                .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
                                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.JWT.getStringValue())
                                .param("response_type", "token id_token")
                                .param("scope", "openid")
                                .param("assertion", assertion)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return (String) JsonUtils.readValueAsMap(json).get("refresh_token");
    }

    private long getRefreshTokenExpClaim(String refreshTokenJtiOrJwt) {
        // The default zone uses OPAQUE refresh token format, so the "refresh_token" field
        // in the response is the JTI. Look up the actual JWT from the revocable token store.
        String jwtValue = refreshTokenJtiOrJwt.contains(".")
                ? refreshTokenJtiOrJwt
                : revocableTokenProvisioning.retrieve(refreshTokenJtiOrJwt, IdentityZoneHolder.get().getId()).getValue();
        String claimsJson = JwtHelper.decode(jwtValue).getClaims();
        Map<String, Object> claims = JsonUtils.readValueAsMap(claimsJson);
        return ((Number) claims.get("exp")).longValue();
    }
}
