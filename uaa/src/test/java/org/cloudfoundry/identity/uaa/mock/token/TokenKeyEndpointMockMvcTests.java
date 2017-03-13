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

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.MapCollector;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.collection.IsMapContaining.hasKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenKeyEndpointMockMvcTests extends InjectedMockContextTest {


    private static final String signKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIIEowIBAAKCAQEA0m59l2u9iDnMbrXHfqkOrn2dVQ3vfBJqcDuFUK03d+1PZGbV\n" +
        "lNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7fYb3d8TjhV86Y997Fl4DBrxgM6KT\n" +
        "JOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQBLCl0vpcXBtFLMaSbpv1ozi8h7DJy\n" +
        "VZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDOkqwIn7Glry9n9Suxygbf8g5AzpWc\n" +
        "usZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPojfj9Cw2QICsc5+Pwf21fP+hzf+1W\n" +
        "SRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nIJwIDAQABAoIBAHPV9rSfzllq16op\n" +
        "zoNetIJBC5aCcU4vJQBbA2wBrgMKUyXFpdSheQphgY7GP/BJTYtifRiS9RzsHAYY\n" +
        "pAlTQEQ9Q4RekZAdd5r6rlsFrUzL7Xj/CVjNfQyHPhPocNqwrkxp4KrO5eL06qcw\n" +
        "UzT7UtnoiCdSLI7IL0hIgJZP8J1uPNdXH+kkDEHE9xzU1q0vsi8nBLlim+ioYfEa\n" +
        "Q/Q/ovMNviLKVs+ZUz+wayglDbCzsevuU+dh3Gmfc98DJw6n6iClpd4fDPqvhxUO\n" +
        "BDeQT1mFeHxexDse/kH9nygxT6E4wlU1sw0TQANcT6sHReyHT1TlwnWlCQzoR3l2\n" +
        "RmkzUsECgYEA8W/VIkfyYdUd5ri+yJ3iLdYF2tDvkiuzVmJeA5AK2KO1fNc7cSPK\n" +
        "/sShHruc0WWZKWiR8Tp3d1XwA2rHMFHwC78RsTds+NpROs3Ya5sWd5mvmpEBbL+z\n" +
        "cl3AU9NLHVvsZjogmgI9HIMTTl4ld7GDsFMt0qlCDztqG6W/iguQCx8CgYEA3x/j\n" +
        "UkP45/PaFWd5c1DkWvmfmi9UxrIM7KeyBtDExGIkffwBMWFMCWm9DODw14bpnqAA\n" +
        "jH5AhQCzVYaXIdp12b+1+eOOckYHwzjWOFpJ3nLgNK3wi067jVp0N0UfgV5nfYw/\n" +
        "+YoHfYRCGsM91fowh7wLcyPPwmSAbQAKwbOZKfkCgYEAnccDdZ+m2iA3pitdIiVr\n" +
        "RaDzuoeHx/IfBHjMD2/2ZpS1aZwOEGXfppZA5KCeXokSimj31rjqkWXrr4/8E6u4\n" +
        "PzTiDvm1kPq60r7qi4eSKx6YD15rm/G7ByYVJbKTB+CmoDekToDgBt3xo+kKeyna\n" +
        "cUQqUdyieunM8bxja4ca3ukCgYAfrDAhomJ30qa3eRvFYcs4msysH2HiXq30/g0I\n" +
        "aKQ12FSjyZ0FvHEFuQvMAzZM8erByKarStSvzJyoXFWhyZgHE+6qDUJQOF6ruKq4\n" +
        "DyEDQb1P3Q0TSVbYRunOWrKRM6xvJvSB4LUVfSvBDsv9TumKqwfZDVFVn9yXHHVq\n" +
        "b6sjSQKBgDkcyYkAjpOHoG3XKMw06OE4OKpP9N6qU8uZOuA8ZF9ZyR7vFf4bCsKv\n" +
        "QH+xY/4h8tgL+eASz5QWhj8DItm8wYGI5lKJr8f36jk0JLPUXODyDAeN6ekXY9LI\n" +
        "fudkijw0dnh28LJqbkFF5wLNtATzyCfzjp+czrPMn9uqLNKt/iVD\n" +
        "-----END RSA PRIVATE KEY-----";
    private static final String verifyKey = "-----BEGIN PUBLIC KEY-----\n" +
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0m59l2u9iDnMbrXHfqkO\n" +
        "rn2dVQ3vfBJqcDuFUK03d+1PZGbVlNCqnkpIJ8syFppW8ljnWweP7+LiWpRoz0I7\n" +
        "fYb3d8TjhV86Y997Fl4DBrxgM6KTJOuE/uxnoDhZQ14LgOU2ckXjOzOdTsnGMKQB\n" +
        "LCl0vpcXBtFLMaSbpv1ozi8h7DJyVZ6EnFQZUWGdgTMhDrmqevfx95U/16c5WBDO\n" +
        "kqwIn7Glry9n9Suxygbf8g5AzpWcusZgDLIIZ7JTUldBb8qU2a0Dl4mvLZOn4wPo\n" +
        "jfj9Cw2QICsc5+Pwf21fP+hzf+1WSRHbnYv8uanRO0gZ8ekGaghM/2H6gqJbo2nI\n" +
        "JwIDAQAB\n" +
        "-----END PUBLIC KEY-----";

    @Before
    public void setUp() throws Exception {
        setUp(signKey);
    }

    public void setUp(String signKey) throws Exception {
        IdentityZoneProvisioning provisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        IdentityZone uaa = provisioning.retrieve("uaa");
        TokenPolicy tokenPolicy = new TokenPolicy();
        tokenPolicy.setKeys(Collections.singletonMap("testKey", signKey));
        uaa.getConfig().setTokenPolicy(tokenPolicy);
        provisioning.update(uaa);
    }

    @Test
    public void checkTokenKeyValues() throws Exception {

        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("app:appclientsecret").getBytes()));

        MvcResult result = getMockMvc().perform(
            get("/token_key")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", basicDigestHeaderValue))
            .andExpect(status().isOk())
            .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    public void get_token_asymmetric_but_authenticated() throws Exception {
        BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(),
                                                         "",
                                                         "foo,bar",
                                                         "client_credentials,password",
                                                         "uaa.none");
        client.setClientSecret("secret");
        getWebApplicationContext().getBean(ClientRegistrationService.class).addClientDetails(client);

        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64((client.getClientId()+":secret").getBytes()));

        MvcResult result = getMockMvc().perform(
            get("/token_key")
                .accept(MediaType.APPLICATION_JSON)
                .header("Authorization", basicDigestHeaderValue))
            .andExpect(status().isOk())
            .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    public void get_token_symmetric_authenticated_but_missing_scope() throws Exception {
        setUp("key");
        try {
            BaseClientDetails client = new BaseClientDetails(new RandomValueStringGenerator().generate(),
                                                             "",
                                                             "foo,bar",
                                                             "client_credentials,password",
                                                             "uaa.none");
            client.setClientSecret("secret");
            getWebApplicationContext().getBean(ClientRegistrationService.class).addClientDetails(client);

            String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64((client.getClientId() + ":secret").getBytes()));

            getMockMvc().perform(
                get("/token_key")
                    .accept(MediaType.APPLICATION_JSON)
                    .header("Authorization", basicDigestHeaderValue))
                .andExpect(status().isForbidden())
                .andReturn();
        } finally {
            setUp(signKey);
        }
    }

    @Test
    public void checkTokenKeyValuesAnonymous() throws Exception {

        MvcResult result = getMockMvc().perform(
            get("/token_key")
                .accept(MediaType.APPLICATION_JSON))
            .andExpect(status().isOk())
            .andReturn();

        Map<String, Object> key = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKey(key);
    }

    @Test
    public void checkTokenKeysValues() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("app:appclientsecret").getBytes()));

        MvcResult result = getMockMvc().perform(
                get("/token_keys")
                        .accept(MediaType.APPLICATION_JSON)
                        .header("Authorization", basicDigestHeaderValue))
                .andExpect(status().isOk())
                .andReturn();

        Map<String, Object> keys = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKeys(keys);
    }

    @Test
    public void checkTokenKeysValuesAnonymous() throws Exception {

        MvcResult result = getMockMvc().perform(
                get("/token_keys")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andDo(print())
                .andReturn();

        Map<String, Object> keys = JsonUtils.readValue(result.getResponse().getContentAsString(), Map.class);
        validateKeys(keys);
    }

    public void validateKey(Map<String,Object> key) {
        Object kty = key.get("kty");
        assertNotNull(kty);
        assertTrue(kty instanceof String);
        assertEquals("RSA", kty);

        Object use = key.get("use"); //optional
        //values for use are
        //1. sig - key used to verify the signature
        //2. enc - key used to
        assertNotNull(use);
        assertTrue(use instanceof String);
        assertEquals("sig", use);


        Object key_ops = key.get("key_ops");
        //an String[] containing values like
        //sign, verify, encrypt, decrypt, wrapKey, unwrapKey, deriveKey, deriveBits
        //should not be used together with 'use' (mutually exclusive)
        assertNull(key_ops);

        Object alg = key.get("alg");
        //optional - algorithm of key
        assertNotNull(alg);
        assertTrue(alg instanceof String);
        assertEquals("RS256", alg);

        Object kid = key.get("kid");
        //optional - indicates the id for a certain key
        //single key doesn't need one
        assertEquals("testKey", kid);

        Object x5u = key.get("x5u");
        //optional - URL that points to a X.509 key or certificate
        assertNull(x5u);

        Object x5c = key.get("x5c");
        //optional - contains a chain of one or more
        //PKIX certificate
        assertNull(x5c);

        Object x5t = key.get("x5t");
        //optional - x509 certificate SHA-1
        assertNull(x5t);

        Object x5tHashS256 = key.get("x5t#S256");
        //optional
        assertNull(x5tHashS256);

        Object actual = key.get("value");
        assertNotNull(actual);
        assertTrue(actual instanceof String);
        assertEquals(verifyKey, actual);


        Object e = key.get("e");
        assertNotNull(e);
        assertTrue(e instanceof String);
        assertEquals("AQAB", e);
        isUrlSafeBase64((String) e);

        Object n = key.get("n");
        assertNotNull(n);
        assertTrue(n instanceof String);
        isUrlSafeBase64((String) n);

    }

    public void validateKeys(Map<String, Object> response) {
        List<Map<String, Object>> keys = (List<Map<String, Object>>)response.get("keys");
        assertNotNull(keys);

        Map<String, ? extends Map<String, Object>> keysMap = keys.stream().collect(new MapCollector<>(k -> (String) k.get("kid"), k -> k));

        assertThat(keysMap, hasKey(is("testKey")));
        validateKey(keysMap.get("testKey"));
    }

    private void isUrlSafeBase64(String base64) {
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        java.util.Base64.Decoder decoder = java.util.Base64.getUrlDecoder();
        assertEquals(base64, encoder.encodeToString(decoder.decode(base64)));
    }

}
