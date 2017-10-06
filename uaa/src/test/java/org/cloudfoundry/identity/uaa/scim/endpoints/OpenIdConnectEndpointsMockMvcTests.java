package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.account.OpenIdConfiguration;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.deleteIdentityZone;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ROLES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class OpenIdConnectEndpointsMockMvcTests extends InjectedMockContextTest {

    private IdentityZone identityZone;

    @Before
    public void setUp() throws Exception {
        identityZone = createOtherIdentityZone("subdomain", getMockMvc(), getWebApplicationContext());
    }

    @After
    public void tearDown() throws Exception {
        deleteIdentityZone(identityZone.getId(), getMockMvc());
    }

    @Test
    public void testWellKnownEndpoint() throws Exception {
        for (String host : Arrays.asList("localhost", "subdomain.localhost")) {
            for (String url : Arrays.asList("/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration")) {
                MockHttpServletResponse response = getMockMvc().perform(
                    get(url)
                        .header("Host", host)
                        .servletPath(url)
                        .with(new SetServerNameRequestPostProcessor(host))
                        .accept(APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andReturn().getResponse();

                OpenIdConfiguration openIdConfiguration = JsonUtils.readValue(response.getContentAsString(), OpenIdConfiguration.class);
                assertNotNull(openIdConfiguration);
                assertEquals("http://"+host+":8080/uaa/oauth/token", openIdConfiguration.getIssuer());
                assertEquals("http://"+host+"/oauth/authorize", openIdConfiguration.getAuthUrl());
                assertEquals("http://"+host+"/oauth/token", openIdConfiguration.getTokenUrl());
                assertArrayEquals(new String[]{"client_secret_basic", "client_secret_post"}, openIdConfiguration.getTokenAMR());
                assertArrayEquals(new String[]{"RS256", "HS256"}, openIdConfiguration.getTokenEndpointAuthSigningValues());
                assertEquals("http://"+host+"/userinfo", openIdConfiguration.getUserInfoUrl());
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
    public void testUserInfoEndpointIsCorrect() throws Exception {
        for (String host : Arrays.asList("localhost", "subdomain.localhost")) {
            for (String url : Arrays.asList("/.well-known/openid-configuration", "/oauth/token/.well-known/openid-configuration")) {
                MockHttpServletResponse response = getMockMvc().perform(
                    get(url)
                        .header("Host", host)
                        .servletPath(url)
                        .with(new SetServerNameRequestPostProcessor(host))
                        .accept(APPLICATION_JSON))
                    .andExpect(status().isOk())
                    .andReturn().getResponse();

                OpenIdConfiguration openIdConfiguration = JsonUtils.readValue(response.getContentAsString(), OpenIdConfiguration.class);

                getMockMvc().perform(get(openIdConfiguration.getUserInfoUrl()))
                    .andExpect(status().isUnauthorized());
            }
        }
    }
}

