package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.account.OpenIdConfiguration;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.deleteIdentityZone;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class OpenIdConnectEndpointsMockMvcTests {

    private IdentityZone identityZone;
    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() throws Exception {
        identityZone = createOtherIdentityZone("subdomain", mockMvc, webApplicationContext, IdentityZoneHolder.getCurrentZoneId());
    }

    @AfterEach
    void tearDown() throws Exception {
        deleteIdentityZone(identityZone.getId(), mockMvc);
    }

    @Test
    void wellKnownEndpoint() throws Exception {
        for (String host : Arrays.asList("localhost", "subdomain.localhost")) {
            for (String url : Arrays.asList("/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration")) {
                MockHttpServletResponse response = mockMvc.perform(
                                get(url)
                                        .header("Host", host)
                                        .servletPath(url)
                                        .with(new SetServerNameRequestPostProcessor(host))
                                        .accept(APPLICATION_JSON))
                        .andExpect(status().isOk())
                        .andReturn().getResponse();

                OpenIdConfiguration openIdConfiguration = JsonUtils.readValue(response.getContentAsString(), OpenIdConfiguration.class);
                assertThat(openIdConfiguration).isNotNull();
                assertThat(openIdConfiguration.getIssuer()).isEqualTo("http://" + host + ":8080/uaa/oauth/token");
                assertThat(openIdConfiguration.getAuthUrl()).isEqualTo("http://" + host + "/oauth/authorize");
                assertThat(openIdConfiguration.getTokenUrl()).isEqualTo("http://" + host + "/oauth/token");
                assertThat(openIdConfiguration.getTokenAMR()).containsExactly(new String[]{"client_secret_basic", "client_secret_post", "private_key_jwt"});
                assertThat(openIdConfiguration.getTokenEndpointAuthSigningValues()).containsExactly(new String[]{"RS256", "HS256"});
                assertThat(openIdConfiguration.getUserInfoUrl()).isEqualTo("http://" + host + "/userinfo");
                assertThat(openIdConfiguration.getScopes()).containsExactly(new String[]{"openid", "profile", "email", "phone", ROLES, USER_ATTRIBUTES});
                assertThat(openIdConfiguration.getResponseTypes()).containsExactly(new String[]{"code", "code id_token", "id_token", "token id_token"});
                assertThat(openIdConfiguration.getIdTokenSigningAlgValues()).containsExactly(new String[]{"RS256", "HS256"});
                assertThat(openIdConfiguration.getClaimTypesSupported()).containsExactly(new String[]{"normal"});
                assertThat(openIdConfiguration.getClaimsSupported()).containsExactly(new String[]{"sub", "user_name", "origin", "iss", "auth_time", "amr", "acr", "client_id",
                        "aud", "zid", "grant_type", "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig", "cid", "given_name", "family_name", "phone_number", "email"});
                assertThat(openIdConfiguration.isClaimsParameterSupported()).isFalse();
                assertThat(openIdConfiguration.getServiceDocumentation()).isEqualTo("http://docs.cloudfoundry.org/api/uaa/");
                assertThat(openIdConfiguration.getUiLocalesSupported()).containsExactly(new String[]{"en-US"});
            }
        }
    }

    @Test
    void userInfoEndpointIsCorrect() throws Exception {
        for (String host : Arrays.asList("localhost", "subdomain.localhost")) {
            for (String url : Arrays.asList("/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration")) {
                MockHttpServletResponse response = mockMvc.perform(
                                get(url)
                                        .header("Host", host)
                                        .servletPath(url)
                                        .with(new SetServerNameRequestPostProcessor(host))
                                        .accept(APPLICATION_JSON))
                        .andExpect(status().isOk())
                        .andReturn().getResponse();

                OpenIdConfiguration openIdConfiguration = JsonUtils.readValue(response.getContentAsString(), OpenIdConfiguration.class);

                mockMvc.perform(get(openIdConfiguration.getUserInfoUrl()))
                        .andExpect(status().isUnauthorized());
            }
        }
    }
}

