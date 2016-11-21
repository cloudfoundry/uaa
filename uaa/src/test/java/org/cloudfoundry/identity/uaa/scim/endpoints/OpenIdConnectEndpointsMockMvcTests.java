package org.cloudfoundry.identity.uaa.scim.endpoints;

import org.cloudfoundry.identity.uaa.account.OpenIdConfiguration;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createOtherIdentityZone;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class OpenIdConnectEndpointsMockMvcTests extends InjectedMockContextTest {

    @Test
    public void testWellKnownEndpoint() throws Exception {
        createOtherIdentityZone("subdomain", getMockMvc(), getWebApplicationContext());
        MockHttpServletResponse response = getMockMvc().perform(get("/.well-known/openid-configuration")
            .with(new SetServerNameRequestPostProcessor("subdomain.localhost"))
            .servletPath("/.well-known/openid-configuration")
            .accept(APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn().getResponse();

        OpenIdConfiguration openIdConfiguration = JsonUtils.readValue(response.getContentAsString(), OpenIdConfiguration.class);
        assertNotNull(openIdConfiguration);
        assertEquals("http://subdomain.localhost:8080/uaa/oauth/token",openIdConfiguration.getIssuer());
        assertEquals("http://subdomain.localhost/oauth/authorize",openIdConfiguration.getAuthUrl());
        assertEquals("http://subdomain.localhost/oauth/token",openIdConfiguration.getTokenUrl());
        assertArrayEquals(new String[]{"client_secret_basic"}, openIdConfiguration.getTokenAMR());
        assertArrayEquals(new String[]{"SHA256withRSA", "HMACSHA256"}, openIdConfiguration.getTokenEndpointAuthSigningValues());
        assertEquals("http://subdomain.localhost/userInfo", openIdConfiguration.getUserInfoUrl());
        assertArrayEquals(new String[]{"openid", "profile", "email", "phone"}, openIdConfiguration.getScopes());
        assertArrayEquals(new String[]{"code", "code id_token", "id_token", "token id_token"}, openIdConfiguration.getResponseTypes());
        assertArrayEquals(new String[]{"SHA256withRSA", "HMACSHA256"}, openIdConfiguration.getIdTokenSigningAlgValues());
        assertArrayEquals(new String[]{"normal"}, openIdConfiguration.getClaimTypesSupported());
        assertArrayEquals(new String[]{"sub", "user_name", "origin", "iss", "auth_time", "amr", "acr", "client_id",
            "aud", "zid", "grant_type", "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig", "cid", "given_name", "family_name", "phone_number", "email"}, openIdConfiguration.getClaimsSupported());
        assertFalse(openIdConfiguration.isClaimsParameterSupported());
        assertEquals("http://docs.cloudfoundry.org/api/uaa/", openIdConfiguration.getServiceDocumentation());
        assertArrayEquals(new String[]{"en-US"}, openIdConfiguration.getUiLocalesSupported());
    }
}

