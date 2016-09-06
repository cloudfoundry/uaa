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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
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
    RandomValueStringGenerator generator;

    String refreshToken;

    @Before
    public void createClientAndUser() throws Exception {
        generator = new RandomValueStringGenerator();
        zone = setupIdentityZone(generator.generate());
        IdentityZoneHolder.set(zone);
        IdentityProvider<UaaIdentityProviderDefinition> provider = setupIdentityProvider();
        assertTrue(provider.isActive());
        IdentityZoneHolder.clear();

        Map<String,String> keys = new HashMap<>();
        keys.put("key1", signingKey1);
        keys.put("key2", signingKey2);
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone.getConfig().getTokenPolicy().setActiveKeyId("key1");
        zone = identityZoneProvisioning.update(zone);

        String clientId = "refresh-"+new RandomValueStringGenerator().generate();
        client = setUpClients(clientId, "uaa.resource", "uaa.user,openid", "client_credentials,password,refresh_token", true, TEST_REDIRECT_URI, Arrays.asList(OriginKeys.UAA), 30*60, zone);

        String username = "testuser"+new RandomValueStringGenerator().generate();
        user = setUpUser(username, "", OriginKeys.UAA, zone.getId());

        refreshToken = getRefreshToken();
    }

    @Test
    public void test_refresh_token_after_key_rotation() throws Exception {

        zone.getConfig().getTokenPolicy().setActiveKeyId("key2");
        zone = identityZoneProvisioning.update(zone);

        testRefresh();

        Map<String,String> keys = new HashMap<>();
        keys.put("key2", signingKey2);
        keys.put("key3", signingKey3);
        zone.getConfig().getTokenPolicy().setKeys(keys);
        zone.getConfig().getTokenPolicy().setActiveKeyId("key3");
        zone = identityZoneProvisioning.update(zone);

        testRefresh();
    }

    protected void testRefresh() throws Exception {
        String refreshResponse = getMockMvc().perform(
            post("/oauth/token")
                .header("Host", zone.getSubdomain()+".localhost")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, REFRESH_TOKEN)
                .param(REFRESH_TOKEN, refreshToken)
                .param("client_secret", SECRET)
                .param(OAuth2Utils.CLIENT_ID, client.getClientId()))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> result = JsonUtils.readValue(refreshResponse, new TypeReference<Map<String, Object>>() {});
        assertNotNull(result.get(ACCESS_TOKEN));
    }


    protected String getRefreshToken() throws Exception {

        String response = getMockMvc().perform(
            post("/oauth/token")
                .header("Host", zone.getSubdomain()+".localhost")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .param(OAuth2Utils.RESPONSE_TYPE, "token")
                .param(OAuth2Utils.GRANT_TYPE, "password")
                .param("username", user.getUserName())
                .param("password", SECRET)
                .param("client_secret", SECRET)
                .param(OAuth2Utils.CLIENT_ID, client.getClientId())
        )
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();

        Map<String,Object> result = JsonUtils.readValue(response, new TypeReference<Map<String, Object>>() {});

        assertNotNull(result.get(REFRESH_TOKEN));
        return (String)result.get(REFRESH_TOKEN);
    }
}
