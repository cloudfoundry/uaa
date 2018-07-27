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
import org.apache.http.HttpStatus;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.oauth.UaaTokenServices;
import org.cloudfoundry.identity.uaa.oauth.jwt.Jwt;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.oauth.openid.IdTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.refresh.RefreshTokenCreator;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.cloudfoundry.identity.uaa.oauth.token.RevocableTokenProvisioning;
import org.cloudfoundry.identity.uaa.oauth.token.TokenConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken.ID_TOKEN;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.ACCESS_TOKEN;
import static org.springframework.security.oauth2.common.OAuth2AccessToken.REFRESH_TOKEN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class RefreshTokenMockMvcTests extends AbstractTokenMockMvcTests {

    String signingKey1 = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOQIBAAJAcPh8sj6TdTGYUTAn7ywyqNuzPD8pNtmSFVm87yCIhKDdIdEQ+g8H\n" +
            "xq8zBWtMN9uaxyEomLXycgTbnduW6YOpyQIDAQABAkAE2qiBAC9V2cuxsWAF5uBG\n" +
            "YSpSbGRY9wBP6oszuzIigLgWwxYwqGSS/Euovn1/BZEQL1JLc8tRp+Zn34JfLrAB\n" +
            "AiEAz956b8BHk2Inbp2FcOvJZI4XVEah5ITY+vTvYFTQEz0CIQCLIN4t+ehu/qIS\n" +
            "fj94nT9LhKPJKMwqhZslC0tIJ4OpfQIhAKaruHhKMBnYpc1nuEsmg8CAvevxBnX4\n" +
            "nxH5usX+uyfxAiA0l7olWyEYRD10DDFmINs6auuXMUrskBDz0e8lWXqV6QIgJSkM\n" +
            "L5WgVmzexrNmKxmGQQhNzfgO0Lk7o+iNNZXbkxw=\n" +
            "-----END RSA PRIVATE KEY-----";

    String signingKey2 = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOQIBAAJBAKIuxhxq0SyeITbTw3SeyHz91eB6xEwRn9PPgl+klu4DRUmVs0h+\n" +
            "UlVjXSTLiJ3r1bJXVded4JzVvNSh5Nw+7zsCAwEAAQJAYeVH8klL39nHhLfIiHF7\n" +
            "5W63FhwktyIATrM4KBFKhXn8i29l76qVqX88LAYpeULric8fGgNoSaYVsHWIOgDu\n" +
            "cQIhAPCJ7hu7OgqvyIGWRp2G2qjKfQVqSntG9HNSt9MhaXKjAiEArJt+PoF0AQFR\n" +
            "R9O/XULmxR0OUYhkYZTr5eCo7kNscokCIDSv0aLrYKxEkqOn2fHZPv3n1HiiLoxQ\n" +
            "H20/OhqZ3/IHAiBSn3/31am8zW+l7UM+Fkc29aij+KDsYQfmmvriSp3/2QIgFtiE\n" +
            "Jkd0KaxkobLdyDrW13QnEaG5TXO0Y85kfu3nP5o=\n" +
            "-----END RSA PRIVATE KEY-----";

    String signingKey3 = "-----BEGIN RSA PRIVATE KEY-----\n" +
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

    String refreshToken;
    private Map<String, String> keys;
    private JdbcTemplate template;
    private RevocableTokenProvisioning revocableTokenProvisioning;
    private TimeService timeService;

    @Before
    public void before() throws Exception {
        timeService = mock(TimeServiceImpl.class);
        UaaTokenServices uaaTokenServices = getWebApplicationContext().getBean(UaaTokenServices.class);
        RefreshTokenCreator refreshTokenCreator = getWebApplicationContext().getBean(RefreshTokenCreator.class);
        IdTokenCreator idTokenCreator = getWebApplicationContext().getBean(IdTokenCreator.class);
        uaaTokenServices.setTimeService(timeService);
        idTokenCreator.setTimeService(timeService);
        refreshTokenCreator.setTimeService(timeService);
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

        String clientId = "refresh-"+new RandomValueStringGenerator().generate();
        client = setUpClients(clientId, "uaa.resource", "uaa.user,openid", "client_credentials,password,refresh_token", true, TEST_REDIRECT_URI, Arrays.asList(OriginKeys.UAA), 30*60, zone);

        String username = "testuser"+new RandomValueStringGenerator().generate();
        user = setUpUser(username, "", OriginKeys.UAA, zone.getId());

        refreshToken = getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");

        revocableTokenProvisioning = getWebApplicationContext().getBean(RevocableTokenProvisioning.class);
        template = getWebApplicationContext().getBean(JdbcTemplate.class);
    }

    @After
    public void reset() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void test_refresh_token_after_key_rotation() throws Exception {
        createClientAndUserInRandomZone();
        zone.getConfig().getTokenPolicy().setActiveKeyId("key2");
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, client.getClientId(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        validateAccessTokenExists(refreshResponse.getContentAsString());

        keys.put("key2", signingKey2);
        keys.put("key3", signingKey3);
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone.getConfig().getTokenPolicy().setActiveKeyId("key3");
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse2 = useRefreshToken(refreshToken, client.getClientId(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(HttpStatus.SC_OK, refreshResponse2.getStatus());
        validateAccessTokenExists(refreshResponse2.getContentAsString());

        keys.remove("key1");
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone = identityZoneProvisioning.update(zone);

        MockHttpServletResponse refreshResponse3 = useRefreshToken(refreshToken, client.getClientId(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(HttpStatus.SC_UNAUTHORIZED, refreshResponse3.getStatus());
    }

    @Test
    public void test_default_refresh_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
    }

    @Test
    public void test_opaque_refresh_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        identityZoneProvisioning.update(zone);
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(2, countTokens(client.getClientId(), user.getId()));
    }

    @Test
    public void test_opaque_refresh_tokens_sets_revocable_claim() throws Exception {
        createClientAndUserInRandomZone();
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        identityZoneProvisioning.update(zone);
        String tokenId = getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        IdentityZoneHolder.set(zone);
        String token = revocableTokenProvisioning.retrieve(tokenId, IdentityZoneHolder.get().getId()).getValue();
        Jwt jwt = JwtHelper.decode(token);
        Map<String, Object> claims = JsonUtils.readValue(jwt.getClaims(), new TypeReference<Map<String, Object>>() {});
        assertNotNull(claims.get(ClaimConstants.REVOCABLE));
        assertTrue((Boolean) claims.get(ClaimConstants.REVOCABLE));
    }

    @Test
    public void test_opaque_refresh_unique_tokens_count() throws Exception {
        createClientAndUserInRandomZone();
        template.update("delete from revocable_tokens");
        zone.getConfig().getTokenPolicy().setRefreshTokenFormat(TokenConstants.TokenFormat.OPAQUE.getStringValue());
        zone.getConfig().getTokenPolicy().setRefreshTokenUnique(true);
        identityZoneProvisioning.update(zone);
        assertEquals(0, countTokens(client.getClientId(), user.getId()));
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        getRefreshToken(client.getClientId(), SECRET, user.getUserName(), SECRET, zone.getSubdomain() + ".localhost");
        assertEquals(1, countTokens(client.getClientId(), user.getId()));
    }

    @Test
    public void refreshTokenGrantType_returnsIdToken_toOpenIdClients() throws Exception {
        when(timeService.getCurrentTimeMillis()).thenReturn(1000L);
        BaseClientDetails openIdClient = setUpClients("openidclient", "", "openid", "password,refresh_token", true);
        ScimUser user = setUpUser("openiduser", "", OriginKeys.UAA, "uaa");
        Map<String, Object> tokenResponse = getTokens(openIdClient.getClientId(), SECRET, user.getUserName(), SECRET, "localhost");
        String refreshToken = (String) tokenResponse.get(REFRESH_TOKEN);
        String originalIdToken = (String) tokenResponse.get(ID_TOKEN);

        when(timeService.getCurrentTimeMillis()).thenReturn(5000L);
        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, openIdClient.getClientId(), SECRET, "localhost");

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeAccessToken compositeAccessToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeAccessToken.class);
        String idTokenJwt = compositeAccessToken.getIdTokenValue();

        assertNotNull(idTokenJwt);
        Map<String, Object> refreshClaims = UaaTokenUtils.getClaims(refreshToken);
        Map<String, Object> originalIdClaims = UaaTokenUtils.getClaims(originalIdToken);
        Map<String, Object> idClaims = UaaTokenUtils.getClaims(idTokenJwt);

        // These claims should be the same in the old and new id tokens: auth_time, iss, sub, azp
        // http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
        assertThat(idClaims.get("auth_time"), not(nullValue()));
        assertEquals(originalIdClaims.get("auth_time"), idClaims.get("auth_time"));

        assertThat(idClaims.get("iss"), not(nullValue()));
        assertEquals(originalIdClaims.get("iss"), idClaims.get("iss"));

        assertThat(refreshClaims.get("sub"), not(nullValue()));
        assertThat(originalIdClaims.get("sub"), not(nullValue()));
        assertEquals(originalIdClaims.get("sub"), idClaims.get("sub"));

        assertThat(idClaims.get("azp"), not(nullValue()));
        assertEquals(originalIdClaims.get("azp"), idClaims.get("azp"));

        // These claims should be different in the old and new id token: iat
        // http://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse
        assertThat(refreshClaims.get("iat"), not(nullValue()));
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

    // TODO: should test with opaque refresh token
    // TODO: iss should not change in id_token even if admin updates issuer config

    @Test
    public void refreshTokenGrantType_doesNotReturnIdToken_toNonOpenIdClients() throws Exception {
        BaseClientDetails nonOpenIdClient = setUpClients("nonopenidclient", "", "scim.me", "password,refresh_token", true);
        ScimUser user = setUpUser("joe-user", "", OriginKeys.UAA, "uaa");
        String refreshToken = getRefreshToken(nonOpenIdClient.getClientId(), SECRET, user.getUserName(), SECRET, "localhost");

        MockHttpServletResponse refreshResponse = useRefreshToken(refreshToken, nonOpenIdClient.getClientId(), SECRET, "localhost");

        assertEquals(HttpStatus.SC_OK, refreshResponse.getStatus());
        CompositeAccessToken compositeAccessToken = JsonUtils.readValue(refreshResponse.getContentAsString(), CompositeAccessToken.class);
        assertNull(compositeAccessToken.getIdTokenValue());
    }

    protected int countTokens(String clientId, String userId) {
        return template.queryForObject("select count(*) from revocable_tokens where client_id=? and user_id=?", new String[] {clientId, userId}, Integer.class);
    }

    protected MockHttpServletResponse useRefreshToken(String refreshToken, String clientId, String clientSecret, String host) throws Exception {
        return getMockMvc().perform(
                post("/oauth/token")
                        .header("Host", host)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, refreshToken)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.CLIENT_ID, clientId))
                .andReturn().getResponse();
    }

    private void validateAccessTokenExists(String refreshResponse) {
        Map<String,Object> result = JsonUtils.readValue(refreshResponse, new TypeReference<Map<String, Object>>() {});
        assertNotNull(result.get(ACCESS_TOKEN));
    }

    protected String getRefreshToken(String clientId, String clientSecret, String userName, String password, String host) throws Exception {
        Map<String, Object> result = getTokens(clientId, clientSecret, userName, password, host);
        assertNotNull(result.get(REFRESH_TOKEN));
        return (String)result.get(REFRESH_TOKEN);
    }

    private Map<String, Object> getTokens(String clientId, String clientSecret, String userName, String password, String host) throws Exception {
        String response = getMockMvc().perform(
                post("/oauth/token")
                        .header("Host", host)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                        .param(OAuth2Utils.RESPONSE_TYPE, "token")
                        .param(OAuth2Utils.GRANT_TYPE, "password")
                        .param("username", userName)
                        .param("password", password)
                        .param("client_secret", clientSecret)
                        .param(OAuth2Utils.CLIENT_ID, clientId)
        )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});
    }
}
