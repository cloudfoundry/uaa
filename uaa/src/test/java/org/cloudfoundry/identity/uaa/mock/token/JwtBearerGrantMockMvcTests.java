/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mock.token;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.junit.Assert.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

@Ignore("auth0 went down June 7, 11:52am Pacific")
public class JwtBearerGrantMockMvcTests extends AbstractTokenMockMvcTests {

    private static RandomValueStringGenerator generator = new RandomValueStringGenerator(12);


    private IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider;
    protected MockMvcUtils.IdentityZoneCreationResult originZone;
    protected BaseClientDetails originClient;
    protected ScimUser originUser;

    @Before
    public void setupJwtBearerTests() throws Exception {
        originClient = new BaseClientDetails(generator.generate(), "", "openid", "password", null);
        originClient.setClientSecret(SECRET);
        String subdomain = generator.generate().toLowerCase();
        originZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), originClient);
        originUser = createUser(originZone.getIdentityZone());
    }

    @After
    public void clearZoneHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void default_zone_jwt_grant () throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(defaultZone,
                getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    public void non_default_zone_jwt_grant () throws Exception {
        String subdomain = generator.generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null).getIdentityZone();
        createProvider(zone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(zone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    public void defaultZoneJwtGrantWithInternalIdp () throws Exception {
        BaseClientDetails defaultZoneClient = new BaseClientDetails(generator.generate(), "", "openid", "password", null);
        defaultZoneClient.setClientSecret(SECRET);

        MockMvcUtils.createClient(getMockMvc(), adminToken, defaultZoneClient);

        IdentityZone defaultZone = IdentityZone.getUaa();

        ScimUser defaultZoneUser = createUser(defaultZone);

        perform_grant_in_zone(defaultZone, getUaaIdToken(defaultZone, defaultZoneClient, defaultZoneUser))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    public void jwtGrantWithInternalIdpWithIdTokenFromDifferentZone () throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        perform_grant_in_zone(defaultZone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
                .andExpect(status().isUnauthorized());
    }

    @Test
    public void assertion_missing() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(defaultZone, null)
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").isNotEmpty())
            .andExpect(jsonPath("$.error_description").isNotEmpty())
            .andExpect(jsonPath("$.error_description").value("Assertion is missing"));
    }

    @Test
    public void signature_mismatch() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, "invalid-verification-key");
        perform_grant_in_zone(defaultZone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").isNotEmpty())
                .andExpect(jsonPath("$.error_description").isNotEmpty())
                .andExpect(jsonPath("$.error_description").value("Could not verify token signature."));
    }

    ResultActions perform_grant_in_zone(IdentityZone theZone, String assertion) throws Exception {

        ClientDetails client = createJwtBearerClient(theZone);

        MockHttpServletRequestBuilder jwtBearerGrant = post("/oauth/token")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("client_id", client.getClientId())
            .param("client_secret", client.getClientSecret())
            .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
            .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE)
            .param("response_type", "token id_token")
            .param("scope", "openid")
            .param("assertion", assertion);

        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain()+".localhost");
        }

        return getMockMvc().perform(jwtBearerGrant)
            .andDo(print());
    }

    void createProvider(IdentityZone theZone, String verificationKey) throws Exception {
        oidcProvider = createOIDCProvider(theZone,
            verificationKey,
            "http://" + originZone.getIdentityZone().getSubdomain() + ".localhost:8080/uaa/oauth/token",
            originClient.getClientId());
    }

    @Test
    @Ignore("auth0 went down June 7, 11:52am Pacific")
    public void auth0_jwt_bearer_grant() throws Exception {
        setup_auth0_jwt_bearer_grant();
    }

    public ResultActions setup_auth0_jwt_bearer_grant() throws Exception {
        IdentityZone theZone = IdentityZone.getUaa();
        String idToken = getAuth0IdToken();
        createAuth0Provider(IdentityZone.getUaa(),
                            "73hk1Cjb49KaDrLjvaU0OU7C2Tyof7pd",
                            "https://cf-identity-eng.auth0.com/.well-known/openid-configuration");

        ClientDetails client = createJwtBearerClient(theZone);

        MockHttpServletRequestBuilder jwtBearerGrant = post("/oauth/token")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("client_id", client.getClientId())
            .param("client_secret", client.getClientSecret())
            .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
            .param("response_type", "token id_token")
            .param("scope", "openid")
            .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.OPAQUE)
            .param("assertion", idToken);

        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain()+".localhost");
        }
        return getMockMvc().perform(jwtBearerGrant)
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty())
            .andExpect(jsonPath("$.id_token").isNotEmpty());
    }

    public String getAuth0IdToken() throws Exception {
        MultiValueMap<String, String> bodyMap = new LinkedMultiValueMap<>();
        bodyMap.add("client_id", "73hk1Cjb49KaDrLjvaU0OU7C2Tyof7pd");
        bodyMap.add("client_secret", "VDJtcBhiksr5uDpcnqF3oDueqGSUe1C0GagdnRGhik2v-6yNENdv-hrh3gPbfvfl");
        bodyMap.add("grant_type", "password");
        bodyMap.add("scope","openid profile");
        bodyMap.add("response_type", "id_token");
        bodyMap.add("connection", "Username-Password-Authentication");
        bodyMap.add("username", "cf-identity-eng+auth0-test@pivotal.io");
        bodyMap.add("password", "96rI#KZ2HvSA");

        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        headers.add(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE);
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        HttpEntity<MultiValueMap<String,String>> body = new HttpEntity<>(bodyMap, headers);

        ResponseEntity<String> response = new RestTemplate().exchange(
            "https://cf-identity-eng.auth0.com/oauth/ro",
            HttpMethod.POST,
            body,
            String.class,
            Collections.emptyMap()
        );

        assertEquals(200, response.getStatusCode().value());
        Map<String, Object> tokenResponse = JsonUtils.readValue(response.getBody(), new TypeReference<Map<String, Object>>() {});
        return (String) tokenResponse.get("id_token");
    }

    public String getUaaIdToken(IdentityZone zone, ClientDetails client, ScimUser user) throws Exception {
        MockHttpServletRequestBuilder passwordGrant = post("/oauth/token")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("client_id", client.getClientId())
            .param("client_secret", client.getClientSecret())
            .param(GRANT_TYPE, "password")
            .param("username", user.getUserName())
            .param("password", SECRET)
            .param("response_type", "id_token");

        if (hasText(zone.getSubdomain())) {
            passwordGrant = passwordGrant.header("Host", zone.getSubdomain()+".localhost");
        }

        String jsonToken = getMockMvc().perform(passwordGrant)
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> token = JsonUtils.readValue(jsonToken, new TypeReference<Map<String, Object>>() {});
        return (String) token.get("id_token");
    }

    public ScimUser createUser(IdentityZone zone) throws Exception {
        String userName = generator.generate().toLowerCase();
        ScimUser user = new ScimUser(null, userName, "first", "last");
        user.setPrimaryEmail(userName+"@test.org");
        IdentityZoneHolder.set(zone);
        try {
            return getWebApplicationContext().getBean(ScimUserProvisioning.class).createUser(user, SECRET, IdentityZoneHolder.get().getId());
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    public ClientDetails createJwtBearerClient(IdentityZone zone) throws Exception {
        BaseClientDetails details = new BaseClientDetails(
            generator.generate().toLowerCase(),
            "",
            "openid",
            GRANT_TYPE_JWT_BEARER,
            null
        );
        details.setClientSecret(SECRET);
        IdentityZoneHolder.set(zone);
        try {
            getWebApplicationContext().getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(details);
        } finally {
            IdentityZoneHolder.clear();
        }
        return details;
    }

    public String getTokenVerificationKey(IdentityZone zone) throws Exception {
        IdentityZoneHolder.set(zone);
        try {
            return KeyInfo.getActiveKey().getVerifierKey();
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    public IdentityProvider<OIDCIdentityProviderDefinition> createAuth0Provider(IdentityZone zone,
                                                                                String clientId,
                                                                                String discoveryUrl) throws Exception {
        String originKey = "auth0-test";
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setDiscoveryUrl(new URL(discoveryUrl));
        definition.setRelyingPartyId(clientId);
        definition.setRelyingPartySecret("never-used");
        definition.setResponseType("id_token");
        definition.setAddShadowUserOnLogin(true);
        definition.addAttributeMapping("user_name", "email");
        IdentityProvider<OIDCIdentityProviderDefinition> auth0Provider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        auth0Provider.setType(OriginKeys.OIDC10);
        auth0Provider.setConfig(definition);
        auth0Provider.setIdentityZoneId(zone.getId());

        JdbcIdentityProviderProvisioning provisioning = getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class);
        provisioning.deleteByOrigin(originKey, zone.getId());
        return provisioning.create(auth0Provider);
    }

    public IdentityProvider<OIDCIdentityProviderDefinition> createOIDCProvider(IdentityZone zone, String tokenKey, String issuer, String relyingPartyId) throws Exception {
        String originKey = generator.generate();
        OIDCIdentityProviderDefinition definition = new OIDCIdentityProviderDefinition();
        definition.setIssuer(issuer);
        definition.setAuthUrl(new URL("http://myauthurl.com"));
        definition.setTokenKey(tokenKey);
        definition.setTokenUrl(null);
        definition.setRelyingPartyId(relyingPartyId);
        definition.setRelyingPartySecret("secret");
        definition.setLinkText("my oidc provider");
        definition.setResponseType("id_token");
        definition.addAttributeMapping("user_name", "email");
        IdentityProvider<OIDCIdentityProviderDefinition> identityProvider = MultitenancyFixture.identityProvider(originKey, zone.getId());
        identityProvider.setType(OriginKeys.OIDC10);
        identityProvider.setConfig(definition);
        IdentityZoneHolder.set(zone);
        try {
            return getWebApplicationContext().getBean(JdbcIdentityProviderProvisioning.class).create(identityProvider);
        } finally {
            IdentityZoneHolder.clear();
        }
    }
}
