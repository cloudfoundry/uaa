/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.token;


import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Lists;
import org.apache.directory.api.util.Base64;
import org.apache.http.HttpStatus;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.TokenValidityResolver;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.*;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static junit.framework.TestCase.assertNull;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_PASSWORD;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.REQUEST_TOKEN_FORMAT;
import static org.cloudfoundry.identity.uaa.util.UaaTokenUtils.getClaims;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class RefreshTokenMockMvcTests extends AbstractTokenMockMvcTests {

    private String signingKey1 = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOQIBAAJAcPh8sj6TdTGYUTAn7ywyqNuzPD8pNtmSFVm87yCIhKDdIdEQ+g8H\n" +
            "xq8zBWtMN9uaxyEomLXycgTbnduW6YOpyQIDAQABAkAE2qiBAC9V2cuxsWAF5uBG\n" +
            "YSpSbGRY9wBP6oszuzIigLgWwxYwqGSS/Euovn1/BZEQL1JLc8tRp+Zn34JfLrAB\n" +
            "AiEAz956b8BHk2Inbp2FcOvJZI4XVEah5ITY+vTvYFTQEz0CIQCLIN4t+ehu/qIS\n" +
            "fj94nT9LhKPJKMwqhZslC0tIJ4OpfQIhAKaruHhKMBnYpc1nuEsmg8CAvevxBnX4\n" +
            "nxH5usX+uyfxAiA0l7olWyEYRD10DDFmINs6auuXMUrskBDz0e8lWXqV6QIgJSkM\n" +
            "L5WgVmzexrNmKxmGQQhNzfgO0Lk7o+iNNZXbkxw=\n" +
            "-----END RSA PRIVATE KEY-----";

    private String signingKey2 = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOQIBAAJBAKIuxhxq0SyeITbTw3SeyHz91eB6xEwRn9PPgl+klu4DRUmVs0h+\n" +
            "UlVjXSTLiJ3r1bJXVded4JzVvNSh5Nw+7zsCAwEAAQJAYeVH8klL39nHhLfIiHF7\n" +
            "5W63FhwktyIATrM4KBFKhXn8i29l76qVqX88LAYpeULric8fGgNoSaYVsHWIOgDu\n" +
            "cQIhAPCJ7hu7OgqvyIGWRp2G2qjKfQVqSntG9HNSt9MhaXKjAiEArJt+PoF0AQFR\n" +
            "R9O/XULmxR0OUYhkYZTr5eCo7kNscokCIDSv0aLrYKxEkqOn2fHZPv3n1HiiLoxQ\n" +
            "H20/OhqZ3/IHAiBSn3/31am8zW+l7UM+Fkc29aij+KDsYQfmmvriSp3/2QIgFtiE\n" +
            "Jkd0KaxkobLdyDrW13QnEaG5TXO0Y85kfu3nP5o=\n" +
            "-----END RSA PRIVATE KEY-----";

    private String signingKey3 = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOgIBAAJBAOnndOyLh8axLMyjX+gCglBCeU5Cumjxz9asho5UvO8zf03PWciZ\n" +
            "DGWce+B+n23E1IXbRKHWckCY0UH7fEgbrKkCAwEAAQJAGR9aCJoH8EhRVn1prKKw\n" +
            "Wmx5WPWDzgfC2fzXyuvBCzPZNMQqOxWT9ajr+VysuyFZbz+HGJDqpf9Jl+fcIIUJ\n" +
            "LQIhAPTn319kLU0QzoNBSB53tPhdNbzggBpW/Xv6B52XqGwPAiEA9IAAFu7GVymQ\n" +
            "/neMHM7/umMFGFFbdq8E2pohLyjcg8cCIQCZWfv/0k2ffQ+jFqSfF1wFTPBSRc1R\n" +
            "MPlmwSg1oPpANwIgHngBCtqQnvYQGpX9QO3O0oRaczBYTI789Nz2O7FE4asCIGEy\n" +
            "SkbkWTex/hl+l0wdNErz/yBxP8esbPukOUqks/if\n" +
            "-----END RSA PRIVATE KEY-----";

    IdentityZone zone;
    ScimUser user;
    BaseClientDetails client;

    private String refreshToken;
    private Map<String, String> keys;
    private TimeService timeService;

    @Autowired
    private TokenValidityResolver refreshTokenValidityResolver;
    @Autowired
    private RefreshTokenCreator refreshTokenCreator;
    @Autowired
    private IdTokenCreator idTokenCreator;
    @Autowired
    private JdbcTemplate template;

    @BeforeEach
    void before() {
        timeService = mock(TimeServiceImpl.class);
        when(timeService.getCurrentDate()).thenCallRealMethod();

        refreshTokenValidityResolver.setTimeService(timeService);
        revocableTokenProvisioning.setTimeService(timeService);
        tokenServices.setTimeService(timeService);
        idTokenCreator.setTimeService(timeService);
        refreshTokenCreator.setTimeService(timeService);
    }

    @AfterEach
    void reset() {
        zone = zone == null ? IdentityZone.getUaa() : zone;
        deleteClient(client.getClientId(), zone.getId());
        deleteUser(user, zone.getId());

        IdentityZoneHolder.clear();
    }

    private void createClientAndUserInRandomZone() throws Exception {
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        zone = setupIdentityZone(generator.generate());
        IdentityZoneHolder.set(zone);
        IdentityProvider<UaaIdentityProviderDefinition> provider = setupIdentityProvider();
        assertTrue(provider.isActive());
        IdentityZoneHolder.clear();

        keys = new HashMap<>();
        keys.put("key1", signingKey1);
        keys.put("key2", signingKey2);
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone.getConfig().getTokenPolicy().setActiveKeyId("key1");
        zone = identityZoneProvisioning.update(zone);

        String clientId = "refreshclient";
        client = setUpClients(clientId, "uaa.resource", "uaa.user,openid", "client_credentials,password,refresh_token", true, TEST_REDIRECT_URI,
                Collections.singletonList(OriginKeys.UAA), 30 * 60, zone);

        String username = "testuser";
        user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, username, "", OriginKeys.UAA, zone.getId());

        refreshToken = getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
    }

    private String getZoneHostUrl(IdentityZone zone) {
        return zone.getSubdomain() + ".localhost";
    }

    @Test
    void refreshTokenGrant_rejectsAccessTokens_ClientCredentialsGrantType() throws Exception {
        createClientAndUserInRandomZone();
        String tokenResponse = mockMvc.perform(
                post("/oauth/token")
                        .header("Host", getZoneHostUrl(zone))
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS)
                        .param("client_secret", SECRET)
                        .param(OAuth2Utils.CLIENT_ID, client.getClientId()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String accessToken = (String)JsonUtils.readValue(tokenResponse, new TypeReference<Map<String, Object>>() {}).get("access_token");

        mockMvc.perform(
            post("/oauth/token")
                    .header("Host", getZoneHostUrl(zone))
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                    .param(REFRESH_TOKEN, accessToken)
                    .param("client_secret", SECRET)
                    .param(OAuth2Utils.CLIENT_ID, client.getClientId()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenGrant_rejectsAccessTokens_PasswordGrantType() throws Exception {
        createClientAndUserInRandomZone();
        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Host", getZoneHostUrl(zone))
                .header("Authorization", "Basic " + new String(Base64.encode((client.getClientId() + ":" + SECRET).getBytes())))
                .param("grant_type", GRANT_TYPE_PASSWORD)
                .param("client_id", client.getClientId())
                .param("client_secret", SECRET)
                .param("username", user.getUserName())
                .param("password", SECRET))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {});
        String accessToken = (String) bodyMap.get("access_token");

        mockMvc.perform(
                post("/oauth/token")
                        .header("Host", getZoneHostUrl(zone))
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, accessToken)
                        .param("client_secret", SECRET)
                        .param(OAuth2Utils.CLIENT_ID, client.getClientId()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void refreshTokenGrant_rejectsIdTokens() throws Exception {
        createClientAndUserInRandomZone();
        String body = mockMvc.perform(post("/oauth/token")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .header("Host", getZoneHostUrl(zone))
                .header("Authorization", "Basic " + new String(Base64.encode((client.getClientId() + ":" + SECRET).getBytes())))
                .param("grant_type", GRANT_TYPE_PASSWORD)
                .param("client_id", client.getClientId())
                .param("client_secret", SECRET)
                .param("username", user.getUserName())
                .param("password", SECRET))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String, Object> bodyMap = JsonUtils.readValue(body, new TypeReference<Map<String, Object>>() {});
        String idToken = (String) bodyMap.get("id_token");

        mockMvc.perform(
            post("/oauth/token")
                .header("Host", getZoneHostUrl(zone))
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, idToken)
                .param("client_secret", SECRET)
                .param(OAuth2Utils.CLIENT_ID, client.getClientId()))
            .andExpect(status().isUnauthorized());
    }

    @Test
    void test_refresh_token_after_key_rotation() throws Exception {
        createClientAndUserInRandomZone();
        zone.getConfig().getTokenPolicy().setActiveKeyId("key2");
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        validateAccessTokenExists(refreshResponse.getContentAsString());

        keys.put("key2", signingKey2);
        keys.put("key3", signingKey3);
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone.getConfig().getTokenPolicy().setActiveKeyId("key3");
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse2 = useRefreshToken(refreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        assertEquals(HttpStatus.SC_OK, refreshResponse2.getStatus());
        validateAccessTokenExists(refreshResponse2.getContentAsString());

        keys.remove("key1");
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse3 = useRefreshToken(refreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, refreshResponse3.getStatus());
    }

    @Test
    void test_default_refresh_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
    }

    @Test
    void test_opaque_refresh_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        identityZoneProvisioning.update(zone);
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        assertEquals(2, countTokens(client.getClientId(), user.getId()));
    }

    @Test
    void test_opaque_refresh_tokens_sets_revocable_claim() throws Exception {
        createClientAndUserInRandomZone();
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        identityZoneProvisioning.update(zone);
        String tokenId = getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        IdentityZoneHolder.set(zone);
        String token = revocableTokenProvisioning.retrieve(tokenId, IdentityZoneHolder.get().getId()).getValue();
        Map<String, Object> claims = UaaTokenUtils.getClaims(token);
        assertNotNull(claims.get(ClaimConstants.REVOCABLE));
        assertTrue((Boolean) claims.get(ClaimConstants.REVOCABLE));
    }

    @Test
    void test_opaque_refresh_unique_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        zone.getConfig().getTokenPolicy().setRefreshTokenUnique(true);
        identityZoneProvisioning.update(zone);
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone));
        assertEquals(1, countTokens(client.getClientId(), user.getId()));
    }

    private void assertRefreshIdTokenCorrect(String originalIdTokenJwt, String idTokenJwtFromRefreshGrant) {
        assertNotNull(idTokenJwtFromRefreshGrant);
        Map<String, Object> originalIdClaims = getClaims(originalIdTokenJwt);
        Map<String, Object> idClaims = getClaims(idTokenJwtFromRefreshGrant);

        // These claims should be the same in the old and new id tokens: auth_time, iss, sub, azp
        // http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
        assertThat(idClaims.get("auth_time"), not(nullValue()));
        assertEquals(originalIdClaims.get("auth_time"), idClaims.get("auth_time"));

        assertThat(idClaims.get("iss"), not(nullValue()));
        assertEquals(originalIdClaims.get("iss"), idClaims.get("iss"));

        assertThat(originalIdClaims.get("sub"), not(nullValue()));
        assertEquals(originalIdClaims.get("sub"), idClaims.get("sub"));

        assertThat(idClaims.get("azp"), not(nullValue()));
        assertEquals(originalIdClaims.get("azp"), idClaims.get("azp"));

        // These claims should be different in the old and new id token: iat
        // http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
        assertThat(originalIdClaims.get("iat"), not(nullValue()));
        assertThat(idClaims.get("iat"), not(nullValue()));
        assertNotEquals(originalIdClaims.get("iat"), idClaims.get("iat"));

        // The spec doesn't say much about these claims in the refresh case, but
        // they still need to be populated according to http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        assertThat(idClaims.get("aud"), not(nullValue()));
        assertThat(originalIdClaims.get("aud"), not(nullValue()));
        assertEquals(originalIdClaims.get("aud"), idClaims.get("aud"));

        assertEquals(Lists.newArrayList("openid"), idClaims.get("scope"));
        assertEquals(Lists.newArrayList("openid"), originalIdClaims.get("scope"));

        assertThat(originalIdClaims.get("amr"), not(nullValue()));
        assertThat(idClaims.get("amr"), not(nullValue()));
        assertEquals(originalIdClaims.get("amr"), idClaims.get("amr"));

        assertThat(originalIdClaims.get("jti"), not(nullValue()));
        assertThat(idClaims.get("jti"), not(nullValue()));
        assertNotEquals(originalIdClaims.get("jti"), idClaims.get("jti"));
    }

    @Test
    void refreshTokenGrantType_returnsIdToken_toOpenIdClients() throws Exception {
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        client = setUpClients("openidclient", "", "openid", "password,refresh_token", true);
        user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "openiduser", "", OriginKeys.UAA, "uaa");
        CompositeToken tokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, "localhost", "jwt");
        String refreshToken = tokenResponse.getRefreshToken().getValue();
        String originalIdTokenJwt = tokenResponse.getIdTokenValue();
        when(timeService.getCurrentTimeMillis()).thenReturn(5000L);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, "localhost");

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeToken compositeToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeToken.class);
        String idTokenJwt = compositeToken.getIdTokenValue();
        assertRefreshIdTokenCorrect(originalIdTokenJwt, idTokenJwt);
    }

    @Test
    void refreshTokenGrantType_returnsIdToken_toOpenIdClients_withOpaqueRefreshToken() throws Exception {
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        client = setUpClients("openidclient", "", "openid", "password,refresh_token", true);
        user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "openiduser", "", OriginKeys.UAA, "uaa");
        CompositeToken tokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, "localhost", "opaque");
        String refreshToken = tokenResponse.getRefreshToken().getValue();
        String originalIdTokenJwt = tokenResponse.getIdTokenValue();
        when(timeService.getCurrentTimeMillis()).thenReturn(5000L);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, "localhost");

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeToken compositeToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeToken.class);
        String idTokenJwt = compositeToken.getIdTokenValue();
        assertRefreshIdTokenCorrect(originalIdTokenJwt, idTokenJwt);
    }

    @Test
    void refreshTokenGrantType_withJwtTokens_preservesRefreshTokenExpiryClaim() throws Exception {
        createClientAndUserInRandomZone();
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        CompositeToken tokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone), "jwt");
        String refreshToken = tokenResponse.getRefreshToken().getValue();
        when(timeService.getCurrentTimeMillis()).thenReturn(5000L);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeToken compositeToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeToken.class);
        String refreshTokenJwt = compositeToken.getRefreshToken().getValue();
        assertThat(getClaims(refreshTokenJwt).get(EXPIRY_IN_SECONDS), equalTo(getClaims(refreshToken).get(EXPIRY_IN_SECONDS)));

        CompositeToken newTokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone), "jwt");
        String newRefreshToken = newTokenResponse.getRefreshToken().getValue();

        assertThat(getClaims(newRefreshToken).get(EXPIRY_IN_SECONDS), not(nullValue()));
        assertThat(getClaims(newRefreshToken).get(EXPIRY_IN_SECONDS), not(equalTo(getClaims(refreshToken).get(EXPIRY_IN_SECONDS))));
    }

    @Test
    void refreshTokenGrantType_withOpaqueTokens_preservesRefreshTokenExpiry() throws Exception {
        createClientAndUserInRandomZone();
        int refreshTokenValiditySeconds = 20;
        client.setRefreshTokenValiditySeconds(refreshTokenValiditySeconds);
        clientDetailsService.updateClientDetails(client, zone.getId());
        long firstGrantMillis = 1000L;
        when(timeService.getCurrentTimeMillis()).thenReturn(firstGrantMillis);
        CompositeToken tokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone), "opaque");
        String firstRefreshToken = tokenResponse.getRefreshToken().getValue();

        long notYetExpiredTimeMillis = 5000L;
        when(timeService.getCurrentTimeMillis()).thenReturn(notYetExpiredTimeMillis);
        MockHttpServletResponse refreshResponse = useRefreshToken(firstRefreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        String secondRefreshToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeToken.class)
                                                .getRefreshToken()
                                                .getValue();
        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());

        long expiredTimeMillis = firstGrantMillis + refreshTokenValiditySeconds * 1000L + 1L;
        when(timeService.getCurrentTimeMillis()).thenReturn(expiredTimeMillis);
        MockHttpServletResponse expiredResponse = useRefreshToken(firstRefreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, expiredResponse.getStatus());
        MockHttpServletResponse alsoExpiredResponse = useRefreshToken(secondRefreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, alsoExpiredResponse.getStatus());
    }

    @Test
    void refreshTokenGrantType_rejectsRefreshTokensIfIssuerHasChanged() throws Exception {
        createClientAndUserInRandomZone();
        zone.getConfig().setIssuer("http://fancyissuer.com");
        identityZoneProvisioning.update(zone);
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        CompositeToken tokenResponse = getTokensWithPasswordGrant(client.getClientId(), SECRET, user.getUserName(), SECRET, getZoneHostUrl(zone), "jwt");
        String refreshToken = tokenResponse.getRefreshToken().getValue();
        when(timeService.getCurrentTimeMillis()).thenReturn(5000L);
        zone.getConfig().setIssuer("http://a.new.issuer.url.com");
        identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, getZoneHostUrl(zone));

        assertEquals(HttpStatus.SC_UNAUTHORIZED, refreshResponse.getStatus());
    }

    @Test
    void refreshTokenGrantType_doesNotReturnIdToken_toNonOpenIdClients() throws Exception {
        client = setUpClients("nonopenidclient", "", "scim.me", "password,refresh_token", true);
        user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "joe-user", "", OriginKeys.UAA, "uaa");
        String refreshToken = getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, "localhost");

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, "localhost");

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeToken compositeToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeToken.class);
        assertNull(compositeToken.getIdTokenValue());
    }

    @Test
    void refreshTokenGrantType_requiresAuthorizedGrantType() throws Exception {
        client = setUpClients("clientwithrefresh", "", "scim.me", "password,refresh_token", true);
        ClientDetails clientWithoutRefresh = setUpClients("passwordclient", "", "scim.me", "password", true);
        user = setUpUser(jdbcScimUserProvisioning, jdbcScimGroupMembershipManager, jdbcScimGroupProvisioning, "joe-user", "", OriginKeys.UAA, "uaa");
        String refreshToken = getJwtRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, "localhost");

        mockMvc.perform(
            post("/oauth/token")
                    .header("Host", "localhost")
                    .accept(MediaType.APPLICATION_JSON)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                    .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                    .param(REFRESH_TOKEN, refreshToken)
                    .param("client_secret", SECRET)
                    .param(OAuth2Utils.CLIENT_ID, clientWithoutRefresh.getClientId()))
            .andExpect(status().isUnauthorized())
            .andExpect(jsonPath("$.error_description").value("Unauthorized grant type: refresh_token"));
    }

    int countTokens(String clientId, String userId) {
        return template.queryForObject("select count(*) from revocable_tokens where client_id=? and user_id=?", new String[]{clientId, userId}, Integer.class);
    }

    MockHttpServletResponse useRefreshToken(String refreshToken, String clientId, String clientSecret, String host) throws Exception {
        return mockMvc.perform(
                post("/oauth/token")
                        .header("Host", host)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, refreshToken)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.CLIENT_ID, clientId))
                .andReturn().getResponse();
    }

    private void validateAccessTokenExists(String refreshResponse) {
        CompositeToken result = JsonUtils.readValue(refreshResponse, CompositeToken.class);
        assertNotNull(result.getValue());
    }

    String getJwtRefreshToken(String clientId, String clientSecret, String userName, String password, String host) throws Exception {
        CompositeToken result = getTokensWithPasswordGrant(clientId, clientSecret, userName, password, host, "jwt");
        assertNotNull(result.getRefreshToken().getValue());
        return result.getRefreshToken().getValue();
    }

    private CompositeToken getTokensWithPasswordGrant(String clientId, String clientSecret, String userName, String password, String host, String tokenFormat) throws Exception {
        String response = mockMvc.perform(
                post("/oauth/token")
                        .header("Host", host)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.GRANT_TYPE, GRANT_TYPE_PASSWORD)
                        .param("username", userName)
                        .param("password", password)
                        .param("client_secret", clientSecret)
                        .param(REQUEST_TOKEN_FORMAT, tokenFormat)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return JsonUtils.readValue(response, CompositeToken.class);
    }
}
