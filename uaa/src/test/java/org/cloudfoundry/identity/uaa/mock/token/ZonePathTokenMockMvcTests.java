package org.cloudfoundry.identity.uaa.mock.token;

import org.assertj.core.api.Assertions;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.mock.util.ZoneResolutionMode;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpMethod;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.authentication.AbstractClientParametersAuthenticationFilter.CLIENT_SECRET;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@EnabledIfZonePathsEnabled
public class ZonePathTokenMockMvcTests extends AbstractTokenMockMvcTests {

    @ParameterizedTest
    @EnumSource(ZoneResolutionMode.class)
    void clientCredentialsGrant(ZoneResolutionMode mode) throws Exception {
        String subdomain = "testzone" + generator.generate().toLowerCase();
        IdentityZone testZone = setupIdentityZone(subdomain);
        IdentityZoneHolder.set(testZone);
        setupIdentityProvider(OriginKeys.UAA);

        String scopes = "uaa.admin";

        String clientId = "testclient" + generator.generate();
        setUpClients(clientId, scopes, scopes, "client_credentials", true, null, null);

        IdentityZoneHolder.clear();

        String tokenResult = mockMvc.perform(mode.createRequestBuilder(subdomain, HttpMethod.GET, "/oauth/token")
                        .accept(APPLICATION_JSON)
                        .contentType(APPLICATION_FORM_URLENCODED)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param(OAuth2Utils.CLIENT_ID, clientId)
                        .param(CLIENT_SECRET, SECRET)
                        .param(OAuth2Utils.REDIRECT_URI, TEST_REDIRECT_URI))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        Map<String, Object> response = JsonUtils.readValueAsMap(tokenResult);
        Jwt tokenClaims = JwtHelper.decode((String) response.get("access_token"));
        Assertions.assertThat(tokenClaims.getClaimSet().getStringClaim(ISS))
                .isEqualTo("http://%s.localhost:8080/uaa/oauth/token".formatted(testZone.getSubdomain()));
    }
}
