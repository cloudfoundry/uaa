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
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.Before;
import org.junit.Test;
import org.springframework.restdocs.snippet.Snippet;

import java.util.Collections;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.restdocs.headers.HeaderDocumentation.headerWithName;
import static org.springframework.restdocs.headers.HeaderDocumentation.requestHeaders;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.preprocessResponse;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint;
import static org.springframework.restdocs.payload.JsonFieldType.STRING;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class TokenKeyEndpointDocs extends InjectedMockContextTest {


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
    public void getTokenAsymmetricAuthenticated() throws Exception {
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("app:appclientsecret").getBytes()));

        Snippet responseFields = responseFields(
            fieldWithPath("kid").type(STRING).description("Key ID of key to be used for verification of the token."),
            fieldWithPath("alg").type(STRING).description("Encryption algorithm"),
            fieldWithPath("value").type(STRING).description("Verifier key"),
            fieldWithPath("kty").type(STRING).description("Key type (RSA)"),
            fieldWithPath("use").type(STRING).description("Public key use parameter - identifies intended use of the public key. (defaults to \"sig\")"),
            fieldWithPath("n").type(STRING).description("RSA key modulus"),
            fieldWithPath("e").type(STRING).description("RSA key public exponent")
        );

        getMockMvc().perform(
            get("/token_key")
                .accept(APPLICATION_JSON)
                .header("Authorization", basicDigestHeaderValue))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()),requestHeaders(
                headerWithName("Authorization").description("No authorization is required for requesting public keys.").optional()
            ), responseFields));
    }

    @Test
    public void getTokenSymmetricAuthenticated() throws Exception {
        setUp("key");
        try {
            String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("app:appclientsecret").getBytes()));

            Snippet responseFields = responseFields(
                fieldWithPath("kid").type(STRING).description("Key ID of key to be used for verification of the token."),
                fieldWithPath("alg").type(STRING).description("Encryption algorithm"),
                fieldWithPath("value").type(STRING).description("Verifier key"),
                fieldWithPath("kty").type(STRING).description("Key type (MAC)"),
                fieldWithPath("use").type(STRING).description("Public key use parameter - identifies intended use of the public key. (defaults to \"sig\")")
            );

            getMockMvc().perform(
                get("/token_key")
                    .accept(APPLICATION_JSON)
                    .header("Authorization", basicDigestHeaderValue))
                .andExpect(status().isOk())
                .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders(
                    headerWithName("Authorization").description("Uses basic authorization with `base64(resource_server:shared_secret)` assuming the caller (a resource server) is actually also a registered client and has `uaa.resource` authority")
                ), responseFields));
        } finally {
            setUp(signKey);
        }
    }

    @Test
    public void checkTokenKeysValues() throws Exception {
        String basicDigestHeaderValue = "Basic "
                + new String(Base64.encodeBase64(("app:appclientsecret").getBytes()));

        Snippet responseFields = responseFields(
            fieldWithPath("keys.[].kid").type(STRING).description("Key ID of key to be used for verification of the token."),
            fieldWithPath("keys.[].alg").type(STRING).description("Encryption algorithm"),
            fieldWithPath("keys.[].value").type(STRING).description("Verifier key"),
            fieldWithPath("keys.[].kty").type(STRING).description("Key type (RSA or MAC)"),
            fieldWithPath("keys.[].use").type(STRING).description("Public key use parameter - identifies intended use of the public key. (defaults to \"sig\")"),
            fieldWithPath("keys.[].n").type(STRING).description("RSA key modulus").optional(),
            fieldWithPath("keys.[].e").type(STRING).description("RSA key public exponent").optional()
        );

        getMockMvc().perform(
            get("/token_keys")
                .accept(APPLICATION_JSON)
                .header("Authorization", basicDigestHeaderValue))
            .andExpect(status().isOk())
            .andDo(document("{ClassName}/{methodName}", preprocessResponse(prettyPrint()), requestHeaders(
                headerWithName("Authorization").description("Basic authorization with `base64(resource_server:shared_secret)` assuming the caller (a resource server) is actually also a registered client and has `uaa.resource` authority. Header not required (anonymous) for obtaining only asymmetric keys. `uaa.resource` authority also not required for obtaining only asymmetric keys should you choose to provide this header.")
            ), responseFields));
    }
}
