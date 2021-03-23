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

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.deleteIdentityZone;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.junit.Assert.*;
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
    void testWellKnownEndpoint() throws Exception {
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
                assertNotNull(openIdConfiguration);
                assertEquals("http://" + host + ":8080/uaa/oauth/token", openIdConfiguration.getIssuer());
                assertEquals("http://" + host + "/oauth/authorize", openIdConfiguration.getAuthUrl());
                assertEquals("http://" + host + "/oauth/token", openIdConfiguration.getTokenUrl());
                assertArrayEquals(new String[]{"client_secret_basic", "client_secret_post"}, openIdConfiguration.getTokenAMR());
                assertArrayEquals(new String[]{"RS256", "HS256"}, openIdConfiguration.getTokenEndpointAuthSigningValues());
                assertEquals("http://" + host + "/userinfo", openIdConfiguration.getUserInfoUrl());
                assertArrayEquals(new String[]{"openid", "profile", "email", "phone", ROLES, USER_ATTRIBUTES}, openIdConfiguration.getScopes());
                assertArrayEquals(new String[]{"code", "code id_token", "id_token", "token id_token"}, openIdConfiguration.getResponseTypes());
                assertArrayEquals(new String[]{"RS256", "HS256"}, openIdConfiguration.getIdTokenSigningAlgValues());
                assertArrayEquals(new String[]{"normal"}, openIdConfiguration.getClaimTypesSupported());
                assertArrayEquals(new String[]{"sub", "user_name", "origin", "iss", "auth_time", "amr", "acr", "client_id",
                        "aud", "zid", "grant_type", "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig", "cid", "given_name", "family_name", "phone_number", "email"}, openIdConfiguration.getClaimsSupported());
                assertFalse(openIdConfiguration.isClaimsParameterSupported());
                assertEquals("http://docs.cloudfoundry.org/api/uaa/", openIdConfiguration.getServiceDocumentation());
                assertArrayEquals(new String[]{"en-US"}, openIdConfiguration.getUiLocalesSupported());
            }
        }
    }

    @Test
    void testUserInfoEndpointIsCorrect() throws Exception {
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

