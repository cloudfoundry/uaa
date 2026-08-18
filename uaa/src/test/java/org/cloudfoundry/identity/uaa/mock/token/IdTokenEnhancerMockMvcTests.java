package org.cloudfoundry.identity.uaa.mock.token;

import tools.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenClaimEnhancer;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenEnhancer;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MvcResult;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.JwtTokenUtils.getClaimsForToken;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.SCOPE;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end coverage for the {@link IdTokenEnhancer} SPI through a real {@code /oauth/token}
 * MockMvc request, closing the gap between the unit-level coverage in
 * {@code IdTokenClaimEnhancerTest}/{@code IdTokenEnhancementContextTest} and the direct-service-call
 * coverage in {@code UaaTokenServicesTests}.
 */
@DisplayName("IdTokenEnhancer SPI, exercised through a real /oauth/token request")
@TestPropertySource(properties = "jwt.token.refresh.format=jwt")
class IdTokenEnhancerMockMvcTests extends AbstractTokenMockMvcTests {

    @AfterEach
    void restoreDefaultEnhancer() {
        tokenServices.setIdTokenClaimEnhancer(IdTokenClaimEnhancer.noOp());
    }

    @Test
    @DisplayName("an enhancer's nested claim on the id_token is derived from the real access- and refresh-token claims")
    void enhancerAddsNestedClaimDerivedFromRealAccessAndRefreshTokenClaims() throws Exception {
        String clientId = "id-token-enhancer-client" + generator.generate();
        setUpClients(clientId, "", "openid", "password,refresh_token", true);
        ScimUser developer = setUpUser(
                jdbcScimUserProvisioning,
                jdbcScimGroupMembershipManager,
                jdbcScimGroupProvisioning,
                "testuser" + generator.generate(),
                "openid",
                OriginKeys.UAA,
                IdentityZoneHolder.get().getId());

        IdTokenEnhancer authInfoEnhancer = enhancementContext -> {
            Map<String, Object> authInfo = new HashMap<>();
            authInfo.put("access_token_id", enhancementContext.getAccessTokenClaim("jti"));
            authInfo.put("refresh_token_id", enhancementContext.getRefreshTokenClaim("jti"));
            authInfo.put("refresh_token_expiration", enhancementContext.getRefreshTokenClaim("exp"));
            enhancementContext.setClaim("auth_info", authInfo);
        };
        tokenServices.setIdTokenClaimEnhancer(new IdTokenClaimEnhancer(List.of(authInfoEnhancer), false));

        MvcResult result = mockMvc.perform(post("/oauth/token")
                        .header(CONTENT_TYPE, APPLICATION_FORM_URLENCODED)
                        .header(ACCEPT, "application/json")
                        .param(GRANT_TYPE, "password")
                        .param(CLIENT_ID, clientId)
                        .param("client_secret", SECRET)
                        .param("username", developer.getUserName())
                        .param("password", SECRET)
                        .param(SCOPE, "openid"))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> tokenResponse = JsonUtils.readValue(
                result.getResponse().getContentAsString(), new TypeReference<Map<String, Object>>() {
                });
        assertThat(tokenResponse).containsKey(ACCESS_TOKEN).containsKey(REFRESH_TOKEN);

        Map<String, Object> idTokenClaims = getClaimsForToken((String) tokenResponse.get("id_token"));
        assertThat(idTokenClaims).containsKey("auth_info");
        @SuppressWarnings("unchecked")
        Map<String, Object> authInfo = (Map<String, Object>) idTokenClaims.get("auth_info");

        Map<String, Object> accessTokenClaims = decodeClaims((String) tokenResponse.get(ACCESS_TOKEN));
        assertThat(authInfo.get("access_token_id")).isEqualTo(accessTokenClaims.get("jti"));

        Map<String, Object> refreshTokenClaims = decodeClaims((String) tokenResponse.get(REFRESH_TOKEN));
        assertThat(authInfo.get("refresh_token_id")).isEqualTo(refreshTokenClaims.get("jti"));
        assertThat(authInfo.get("refresh_token_expiration")).isEqualTo(refreshTokenClaims.get("exp"));
    }

    private static Map<String, Object> decodeClaims(String jwt) {
        return JsonUtils.readValue(JwtHelper.decode(jwt).getClaims(), new TypeReference<Map<String, Object>>() {
        });
    }
}
