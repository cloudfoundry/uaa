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
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public class JwtBearerGrantMockMvcTests extends AbstractTokenMockMvcTests {

    private static RandomValueStringGenerator generator = new RandomValueStringGenerator(12);

    MockMvcUtils.IdentityZoneCreationResult originZone;
    BaseClientDetails originClient;
    ScimUser originUser;

    @BeforeEach
    public void setupJwtBearerTests() throws Exception {
        originClient = new BaseClientDetails(generator.generate(), "", "openid", "password", null);
        originClient.setClientSecret(SECRET);
        String subdomain = generator.generate().toLowerCase();
        originZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, originClient);
        originUser = createUser(originZone.getIdentityZone());
    }

    @AfterEach
    public void clearZoneHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    void default_zone_jwt_grant() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(defaultZone,
                getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void non_default_zone_jwt_grant() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                                                                                mockMvc,
                                                                                webApplicationContext,
                                                                                null,
                                                                                false).getIdentityZone();
        createProvider(zone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(zone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void defaultZoneJwtGrantWithInternalIdp() throws Exception {
        BaseClientDetails defaultZoneClient = setUpClients(generator.generate(), "", "openid", "password", true);
        defaultZoneClient.setClientSecret(SECRET);

        IdentityZone defaultZone = IdentityZone.getUaa();

        ScimUser defaultZoneUser = createUser(defaultZone);

        perform_grant_in_zone(defaultZone, getUaaIdToken(defaultZone, defaultZoneClient, defaultZoneUser))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    @Test
    void jwtGrantWithInternalIdpWithIdTokenFromDifferentZone() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        perform_grant_in_zone(defaultZone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void assertion_missing() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(defaultZone, null)
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error").isNotEmpty())
            .andExpect(jsonPath("$.error_description").isNotEmpty())
            .andExpect(jsonPath("$.error_description").value("Assertion is missing"));
    }

    @Test
    void signature_mismatch() throws Exception {
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
            .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.OPAQUE.getStringValue())
            .param("response_type", "token id_token")
            .param("scope", "openid")
            .param("assertion", assertion);

        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain()+".localhost");
        }

        return mockMvc.perform(jwtBearerGrant)
            .andDo(print());
    }

    void createProvider(IdentityZone theZone, String verificationKey) throws Exception {
        createOIDCProvider(theZone,
                verificationKey,
                "http://" + originZone.getIdentityZone().getSubdomain() + ".localhost:8080/uaa/oauth/token",
                originClient.getClientId());
    }

    String getUaaIdToken(IdentityZone zone, ClientDetails client, ScimUser user) throws Exception {
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

        String jsonToken = mockMvc.perform(passwordGrant)
            .andDo(print())
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> token = JsonUtils.readValue(jsonToken, new TypeReference<Map<String, Object>>() {});
        return (String) token.get("id_token");
    }

    public ScimUser createUser(IdentityZone zone) {
        String userName = generator.generate().toLowerCase();
        ScimUser user = new ScimUser(null, userName, "first", "last");
        user.setPrimaryEmail(userName+"@test.org");
        IdentityZoneHolder.set(zone);
        try {
            return webApplicationContext.getBean(ScimUserProvisioning.class).createUser(user, SECRET, IdentityZoneHolder.get().getId());
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    ClientDetails createJwtBearerClient(IdentityZone zone) {
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
            webApplicationContext.getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(details);
        } finally {
            IdentityZoneHolder.clear();
        }
        return details;
    }

    String getTokenVerificationKey(IdentityZone zone) {
        IdentityZoneHolder.set(zone);
        try {
            return new KeyInfoService("https://someurl").getActiveKey().verifierKey();
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    IdentityProvider<OIDCIdentityProviderDefinition> createOIDCProvider(IdentityZone zone, String tokenKey, String issuer, String relyingPartyId) throws Exception {
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
            return webApplicationContext.getBean(JdbcIdentityProviderProvisioning.class).create(identityProvider, zone.getId());
        } finally {
            IdentityZoneHolder.clear();
        }
    }
}
