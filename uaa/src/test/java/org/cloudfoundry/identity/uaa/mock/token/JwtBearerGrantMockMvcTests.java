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
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.JwtTokenUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.List;
import java.util.Map;

import static java.util.Collections.emptyMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.util.StringUtils.hasText;

public class JwtBearerGrantMockMvcTests extends AbstractTokenMockMvcTests {

    private static final RandomValueStringGenerator generator = new RandomValueStringGenerator(12);

    MockMvcUtils.IdentityZoneCreationResult originZone;
    UaaClientDetails originClient;
    ScimUser originUser;

    @BeforeEach
    void setupJwtBearerTests() throws Exception {
        originClient = new UaaClientDetails(generator.generate(), "", "openid", "password", null);
        originClient.setClientSecret(SECRET);
        String subdomain = generator.generate().toLowerCase();
        originZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain, mockMvc, webApplicationContext, originClient, IdentityZoneHolder.getCurrentZoneId());
        originUser = createUser(originZone.getIdentityZone());
    }

    @AfterEach
    void clearZoneHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    void default_zone_jwt_grant() throws Exception {
        IdentityZone defaultZone = IdentityZone.getUaa();
        createProvider(defaultZone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(defaultZone,
                getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty());
    }

    @Test
    void non_default_zone_jwt_grant_user_update() throws Exception {
        UaaClientDetails targetZoneClient = new UaaClientDetails(generator.generate(), "", "openid", "password", null);
        targetZoneClient.setClientSecret(SECRET);
        String subdomain = generator.generate().toLowerCase();
        IdentityZone targetZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                mockMvc,
                webApplicationContext,
                targetZoneClient,
                false, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
        ScimUser targetZoneUser = createUser(targetZone);

        String originZoneOriginKey = createProvider(targetZone, getTokenVerificationKey(originZone.getIdentityZone()));

        //Check for internal User
        String targetZoneIdToken = getUaaIdToken(targetZone, targetZoneClient, targetZoneUser);
        String accessTokenForTargetZoneUser = performJWTBearerGrantForJWT(targetZone, targetZoneIdToken);

        //Verify JWT Bearer did not change values of internal User
        ScimUser targetUserAfterGrant = getScimUser(targetZoneUser.getUserName(), OriginKeys.UAA, targetZone.getId());
        assertThat(targetUserAfterGrant.getUserName()).isEqualTo(targetZoneUser.getUserName());
        assertThat(targetUserAfterGrant.getExternalId()).isEqualTo(targetZoneUser.getExternalId());

        //Check for user of registered IdP
        String originZoneIdToken = getUaaIdToken(originZone.getIdentityZone(), originClient, originUser);
        String accessTokenForOriginZoneUser = performJWTBearerGrantForJWT(targetZone, originZoneIdToken);
        Map<String, Object> originUserClaims = JwtTokenUtils.getClaimsForToken(accessTokenForOriginZoneUser);

        //Verify values for new shadow user set
        ScimUser shadowUser = getScimUser(originUser.getEmails().getFirst().getValue(), originZoneOriginKey, targetZone.getId());
        assertThat(originUserClaims).containsEntry("user_name", shadowUser.getUserName());
        assertThat(originUser.getId()).isEqualTo(shadowUser.getExternalId());

        //JWT Bearer with token from target Zone and external User
        performJWTBearerGrantForJWT(targetZone, accessTokenForOriginZoneUser);

        //Verify username and External ID not changed after this internal grant
        ScimUser shadowUserAfterExchange = getScimUser(originUser.getEmails().getFirst().getValue(), originZoneOriginKey, targetZone.getId());
        assertThat(shadowUserAfterExchange.getUserName()).isEqualTo(shadowUser.getUserName());
        assertThat(shadowUserAfterExchange.getExternalId()).isEqualTo(shadowUser.getExternalId());
    }

    @Test
    void non_default_zone_jwt_grant_user_update_same_zone_with_registration() throws Exception {
        UaaClientDetails targetZoneClient = new UaaClientDetails(generator.generate(), "", "openid", "password",
                null);
        targetZoneClient.setClientSecret(SECRET);
        String subdomain = generator.generate().toLowerCase();
        IdentityZone targetZone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                mockMvc,
                webApplicationContext,
                targetZoneClient,
                false, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
        ScimUser targetZoneUser = createUser(targetZone);

        String originZoneOriginKey = createOIDCProvider(targetZone,
                getTokenVerificationKey(targetZone),
                "http://" + targetZone.getSubdomain() + ".localhost:8080/uaa/oauth/token",
                targetZoneClient.getClientId()).getOriginKey();

        String targetZoneIdToken = getUaaIdToken(targetZone, targetZoneClient, targetZoneUser);
        String accessTokenForTargetZoneUser = performJWTBearerGrantForJWT(targetZone, targetZoneIdToken);

        Map<String, Object> targetUserClaims = JwtTokenUtils.getClaimsForToken(accessTokenForTargetZoneUser);

        //Verify shadow user of same-zone Idp created
        ScimUser originShadowUser = getScimUser(targetZoneUser.getEmails().getFirst().getValue(), originZoneOriginKey, targetZone.getId());
        assertThat(targetUserClaims).containsEntry("user_name", originShadowUser.getUserName());
        assertThat(targetZoneUser.getId()).isEqualTo(originShadowUser.getExternalId());

        //JWT Bearer with token from target Zone and shadow user of registered IdP (with same issuer)
        performJWTBearerGrantForJWT(targetZone, accessTokenForTargetZoneUser);

        //Verify username and External ID changed after this internal grant (as they are updated values of registered issuer)
        ScimUser originShadowUserAfterExchange = getScimUser(targetZoneUser.getEmails().getFirst().getValue(), originZoneOriginKey, targetZone.getId());
        assertThat(targetUserClaims)
                .containsEntry("user_name", originShadowUserAfterExchange.getUserName())
                .containsEntry("sub", originShadowUserAfterExchange.getExternalId());
    }

    @Test
    void non_default_zone_jwt_grant() throws Exception {
        String subdomain = generator.generate().toLowerCase();
        IdentityZone zone = MockMvcUtils.createOtherIdentityZoneAndReturnResult(subdomain,
                mockMvc,
                webApplicationContext,
                null,
                false, IdentityZoneHolder.getCurrentZoneId()).getIdentityZone();
        createProvider(zone, getTokenVerificationKey(originZone.getIdentityZone()));
        perform_grant_in_zone(zone, getUaaIdToken(originZone.getIdentityZone(), originClient, originUser))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty());
    }

    @Test
    void defaultZoneJwtGrantWithInternalIdp() throws Exception {
        UaaClientDetails defaultZoneClient = setUpClients(generator.generate(), "", "openid", "password", true);
        defaultZoneClient.setClientSecret(SECRET);

        IdentityZone defaultZone = IdentityZone.getUaa();

        ScimUser defaultZoneUser = createUser(defaultZone);

        perform_grant_in_zone(defaultZone, getUaaIdToken(defaultZone, defaultZoneClient, defaultZoneUser))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty());
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
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.OPAQUE.getStringValue())
                .param("response_type", "token id_token")
                .param("scope", "openid")
                .param("login_hint", "%7B%22origin%22%3A%22idp%22%7D")
                .param("assertion", assertion);

        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain() + ".localhost");
        }

        return mockMvc.perform(jwtBearerGrant)
                .andDo(print());
    }

    private String performJWTBearerGrantForJWT(IdentityZone theZone, String assertion) throws Exception {
        ClientDetails client = createJwtBearerClient(theZone);

        MockHttpServletRequestBuilder jwtBearerGrant = post("/oauth/token")
                .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param("client_id", client.getClientId())
                .param("client_secret", client.getClientSecret())
                .param("client_assertion", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZDU1YzUwMGNjNmI1ODM3OTYxN2UwNmU3ZGVjNmNhIn0.eyJzdWIiOiJsb2dpbiIsImlzcyI6ImxvZ2luIiwianRpIjoiNThkNTVjNTAwY2M2YjU4Mzc5NjE3ZTA2ZTdhZmZlZSIsImV4cCI6MTIzNDU2NzgsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4ifQ.jwWw0OKZecd4ZjtwQ_ievqBVrh2SieqMF6vY74Oo5H6v-Ibcmumq96NLNtoUEwaAEQQOHb8MWcC8Gwi9dVQdCrtpomC86b_LKkihRBSKuqpw0udL9RMH5kgtC04ctsN0yZNifUWMP85VHn97Ual5eZ2miaBFob3H5jUe98CcBj1TSRehr64qBFYuwt9vD19q6U-ONhRt0RXBPB7ayHAOMYtb1LFIzGAiKvqWEy9f-TBPXSsETjKkAtSuM-WVWi4EhACMtSvI6iJN15f7qlverRSkGIdh1j2vPXpKKBJoRhoLw6YqbgcUC9vAr17wfa_POxaRHvh9JPty0ZXLA4XPtA")
                .param("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .param(GRANT_TYPE, GRANT_TYPE_JWT_BEARER)
                .param(TokenConstants.REQUEST_TOKEN_FORMAT, TokenConstants.TokenFormat.JWT.getStringValue())
                .param("response_type", "token id_token")
                .param("scope", "openid")
                .param("login_hint", "%7B%22origin%22%3A%22idp%22%7D")
                .param("assertion", assertion);
        if (hasText(theZone.getSubdomain())) {
            jwtBearerGrant = jwtBearerGrant.header("Host", theZone.getSubdomain() + ".localhost");
        }
        String tokenResponse = mockMvc.perform(jwtBearerGrant)
                .andDo(print())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andReturn()
                .getResponse()
                .getContentAsString();
        Map<String, Object> tokenMap = JsonUtils.readValue(tokenResponse, Map.class);
        return (String) tokenMap.get("access_token");
    }

    String createProvider(IdentityZone theZone, String verificationKey) throws Exception {
        IdentityProvider idp = createOIDCProvider(theZone,
                verificationKey,
                "http://" + originZone.getIdentityZone().getSubdomain() + ".localhost:8080/uaa/oauth/token",
                originClient.getClientId());
        return idp.getOriginKey();
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
            passwordGrant = passwordGrant.header("Host", zone.getSubdomain() + ".localhost");
        }

        String jsonToken = mockMvc.perform(passwordGrant)
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> token = JsonUtils.readValue(jsonToken, new TypeReference<Map<String, Object>>() {
        });
        return (String) token.get("id_token");
    }

    public ScimUser createUser(IdentityZone zone) {
        String userName = generator.generate().toLowerCase();
        ScimUser user = new ScimUser(null, userName, "first", "last");
        user.setPrimaryEmail(userName + "@test.org");
        IdentityZoneHolder.set(zone);
        try {
            return webApplicationContext.getBean(ScimUserProvisioning.class).createUser(user, SECRET, IdentityZoneHolder.get().getId());
        } finally {
            IdentityZoneHolder.clear();
        }
    }

    private ScimUser getScimUser(String username, String origin, String zoneId) {
        ScimUserProvisioning scimUserProvisioning = webApplicationContext.getBean(ScimUserProvisioning.class);

        List<ScimUser> scimUsers = scimUserProvisioning.retrieveByUsernameAndOriginAndZone(username, origin, zoneId);
        assertThat(scimUsers).hasSize(1);
        return scimUsers.getFirst();
    }

    ClientDetails createJwtBearerClient(IdentityZone zone) {

        UaaClientDetails details =  setUpClients(
                generator.generate().toLowerCase(),
                "",
                "openid",
                GRANT_TYPE_JWT_BEARER + "," + GRANT_TYPE_REFRESH_TOKEN,
                List.of("openid"),
                null,
                null,
                -1,
                zone,
                emptyMap()
        );
        details.setClientSecret(SECRET);
        return details;
    }


}
