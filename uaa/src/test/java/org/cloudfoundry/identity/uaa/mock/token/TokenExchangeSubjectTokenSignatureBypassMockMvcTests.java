package org.cloudfoundry.identity.uaa.mock.token;

import tools.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenExchangeData;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.Authentication;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests that verify {@link TokenExchangeGranter} performs its own
 * {@code subject_token} signature verification, independently of the filter layer.
 *
 * <p>The default {@code tokenExchangeAuthenticationManager} is marked
 * {@code @ConditionalOnMissingBean}, so operators and extensions can supply a
 * replacement.  If that replacement weakens or omits signature verification, the
 * granter must still reject tokens whose signatures do not match the keys published
 * by the registered identity provider.
 *
 * <p>This test class registers such a replacement — one that skips
 * {@code validateToken()} in the filter layer — then submits a tampered
 * {@code subject_token}.  The granter's independent verification (via
 * {@code ExternalOAuthAuthenticationManager#verifySubjectToken}) must catch the
 * invalid signature and return HTTP 400 {@code invalid_grant}.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(TokenExchangeSubjectTokenSignatureBypassMockMvcTests.NoSignatureVerificationConfig.class)
@DefaultTestContext
class TokenExchangeSubjectTokenSignatureBypassMockMvcTests extends TokenExchangeMockMvcBase {

    /**
     * Replaces the default {@code tokenExchangeAuthenticationManager} with a subclass
     * that skips signature verification in the filter layer.
     *
     * <p>Only {@code getClaimsFromToken(String, IdentityProvider)} is overridden: it
     * decodes the JWT payload directly without calling {@code validateToken()}, so any
     * token — including one with a tampered payload — is accepted at the filter.  All
     * other behaviour (user lookup, shadow-user creation, issuer-based IdP resolution)
     * is inherited from the base class unchanged.
     *
     * <p>Note that {@code verifySubjectToken()} is NOT overridden, so the granter's
     * call to that method still runs the real {@code validateToken()} and detects the
     * invalid signature.
     */
    static class NoSignatureVerificationConfig {

        @Bean("tokenExchangeAuthenticationManager")
        ExternalOAuthAuthenticationManager tokenExchangeAuthenticationManager(
                @Qualifier("externalOAuthProviderConfigurator") IdentityProviderProvisioning providerProvisioning,
                @Qualifier("identityZoneManager") org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager identityZoneManager,
                @Qualifier("trustingRestTemplate") RestTemplate trustingRestTemplate,
                @Qualifier("nonTrustingRestTemplate") RestTemplate nonTrustingRestTemplate,
                @Qualifier("tokenEndpointBuilder") TokenEndpointBuilder tokenEndpointBuilder,
                @Qualifier("keyInfoService") KeyInfoService keyInfoService,
                @Qualifier("oidcMetadataFetcher") OidcMetadataFetcher oidcMetadataFetcher,
                @Qualifier("userDatabase") UaaUserDatabase userDatabase,
                @Qualifier("externalGroupMembershipManager") ScimGroupExternalMembershipManager externalMembershipManager
        ) {
            ExternalOAuthAuthenticationManager bean = new ExternalOAuthAuthenticationManager(
                    providerProvisioning,
                    identityZoneManager,
                    trustingRestTemplate,
                    nonTrustingRestTemplate,
                    tokenEndpointBuilder,
                    keyInfoService,
                    oidcMetadataFetcher,
                    false
            ) {
                /**
                 * Simulates a filter-layer implementation that skips {@code validateToken()}.
                 * Decodes the JWT payload directly and returns the claims map without any
                 * cryptographic check.
                 */
                @Override
                protected <T extends AbstractExternalOAuthIdentityProviderDefinition<T>>
                Map<String, Object> getClaimsFromToken(String idToken, IdentityProvider<T> identityProvider) {
                    String[] parts = idToken.split("\\.");
                    String json = new String(
                            Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
                    return JsonUtils.readValue(json, new TypeReference<>() {});
                }

                /**
                 * Mirrors the access-token → id-token field swap that the default
                 * {@link org.cloudfoundry.identity.uaa.provider.oauth.TokenExchangeWrapperForExternalOauth}
                 * performs, ensuring the token string is available for {@code iss}-based
                 * IdP resolution regardless of {@code subject_token_type}.
                 */
                @Override
                public Authentication authenticate(Authentication authentication) {
                    ExternalOAuthCodeToken token = (ExternalOAuthCodeToken) authentication;
                    if (token.getIdToken() == null) {
                        token = new TokenExchangeData(
                                token.getCode(),
                                token.getOrigin(),
                                token.getRedirectUrl(),
                                token.getAccessToken(),
                                token.getAccessToken(),
                                token.getSignedRequest(),
                                token.getUaaAuthenticationDetails()
                        );
                    }
                    return super.authenticate(token);
                }
            };
            bean.setUserDatabase(userDatabase);
            bean.setExternalMembershipManager(externalMembershipManager);
            return bean;
        }
    }

    /**
     * Verifies that {@code TokenExchangeGranter} independently validates the
     * {@code subject_token} signature even when the filter layer skipped that check.
     *
     * <p>Steps:
     * <ol>
     *   <li>Obtain a legitimately signed {@code access_token} from the control server.</li>
     *   <li>Replace its {@code sub} and {@code user_id} claims while keeping the original
     *       {@code iss} and signature.  The {@code iss} is left intact so that the registered
     *       IdP can be resolved by the granter; the signature is now cryptographically invalid
     *       for the modified payload.</li>
     *   <li>Submit the tampered JWT as {@code subject_token}.  The filter-layer auth manager
     *       ({@code NoSignatureVerificationConfig}) accepts it without a signature check.</li>
     *   <li>The granter calls {@code ExternalOAuthAuthenticationManager#verifySubjectToken},
     *       which resolves the IdP by {@code iss} and verifies the signature against the
     *       IdP's published keys.  The mismatch must produce HTTP 400 {@code invalid_grant}.</li>
     * </ol>
     */
    @Test
    void tampered_subject_token_is_rejected_by_granter_even_when_filter_skips_sig_check()
            throws Exception {
        ThreeWayUAASetup setup = getThreeWayUaaSetUp();
        AuthorizationServer workerServer = setup.workerServer();

        String legitimateJwt = (String) setup.controlServerTokens().get("access_token");

        // Tamper sub and user_id; leave iss intact so the IdP is resolved by issuer.
        String[] parts = legitimateJwt.split("\\.");
        Map<String, Object> originalClaims = JsonUtils.readValueAsMap(
                new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));

        originalClaims.put(ClaimConstants.SUB,     "FORGED-" + originalClaims.get(ClaimConstants.SUB));
        originalClaims.put(ClaimConstants.USER_ID, "FORGED-" + originalClaims.get(ClaimConstants.USER_ID));

        // Re-encode the tampered payload; the original signature no longer covers it.
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JsonUtils.writeValueAsString(originalClaims)
                        .getBytes(StandardCharsets.UTF_8));

        // Original header · tampered payload · original (now-invalid) signature.
        String tamperedJwt = parts[0] + "." + tamperedPayload + "." + parts[2];

        ResultActions result = performTokenExchangeGrantForJWT(
                workerServer.zone().getIdentityZone(),
                tamperedJwt,
                TOKEN_TYPE_ACCESS,
                TOKEN_TYPE_ACCESS,
                null, null,
                workerServer.client(),
                ClientAuthType.FORM,
                null
        );

        // The granter's verifySubjectToken() resolves the IdP by iss and detects the
        // invalid signature → HTTP 400 invalid_grant.
        result.andExpect(status().isBadRequest())
              .andExpect(jsonPath("$.error").value("invalid_grant"));
    }
}
