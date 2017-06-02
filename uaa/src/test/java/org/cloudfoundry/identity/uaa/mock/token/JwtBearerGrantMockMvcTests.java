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
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
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


    private IdentityProvider<OIDCIdentityProviderDefinition> oidcProvider;
    private MockMvcUtils.IdentityZoneCreationResult originZone;
    private BaseClientDetails originClient;
    private ScimUser originUser;

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
    public void jwt_bearer_grant_default_zone() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        ClientDetails client = createJwtBearerClient(defaultZone);
        oidcProvider =
            createOIDCProvider(defaultZone,
                               getTokenVerificationKey(originZone.getIdentityZone()),
                               "http://"+originZone.getIdentityZone().getSubdomain()+".localhost:8080/uaa/oauth/token",
                               originClient.getClientId());

        String idToken = getIdToken(originZone.getIdentityZone(), originClient, originUser);

        MockHttpServletRequestBuilder jwtBearerGrant = post("/oauth/token")
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
            .param("client_id", client.getClientId())
            .param("client_secret", client.getClientSecret())
            .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
            .param("assertion", idToken);

        if (hasText(defaultZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", defaultZone.getSubdomain()+".localhost");
        }

        getMockMvc().perform(jwtBearerGrant)
            .andDo(print())
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.access_token").isNotEmpty());
    }

    public String getIdToken(IdentityZone zone, ClientDetails client, ScimUser user) throws Exception {
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
            return getWebApplicationContext().getBean(ScimUserProvisioning.class).createUser(user, SECRET);
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
