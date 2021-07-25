/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.*;

import static java.util.Collections.singletonMap;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class ChainedSignatureVerifierTests {
    private Signer signer;
    private Signer invalidSigner;

    private String rsaSigningKey;
    private String invalidRsaSigningKey;

    private String content;
    private Jwt signedValidContent;

    private JsonWebKey validKey;
    private JsonWebKey invalidKey;
    private ChainedSignatureVerifier verifier;
    private KeyInfo keyInfo;


    @Before
    public void setup() {
        rsaSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
          "MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T\n" +
          "PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo\n" +
          "hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB\n" +
          "AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA\n" +
          "BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj\n" +
          "RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3\n" +
          "2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=\n" +
          "-----END RSA PRIVATE KEY-----";

        invalidRsaSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
          "MIIBOgIBAAJBAJnlBG4lLmUiHslsKDODfd0MqmGZRNUOhn7eO3cKobsFljUKzRQe\n" +
          "GB7LYMjPavnKccm6+jWSXutpzfAc9A9wXG8CAwEAAQJADwwdiseH6cuURw2UQLUy\n" +
          "sVJztmdOG6b375+7IMChX6/cgoF0roCPP0Xr70y1J4TXvFhjcwTgm4RI+AUiIDKw\n" +
          "gQIhAPQHwHzdYG1639Qz/TCHzuai0ItwVC1wlqKpat+CaqdZAiEAoXFyS7249mRu\n" +
          "xtwRAvxKMe+eshHvG2le+ZDrM/pz8QcCIQCzmCDpxGL7L7sbCUgFN23l/11Lwdex\n" +
          "uXKjM9wbsnebwQIgeZIbVovUp74zaQ44xT3EhVwC7ebxXnv3qAkIBMk526sCIDVg\n" +
          "z1jr3KEcaq9zjNJd9sKBkqpkVSqj8Mv+Amq+YjBA\n" +
          "-----END RSA PRIVATE KEY-----";

        invalidSigner = new CommonSigner("invalid", invalidRsaSigningKey, "http://localhost/uaa");

        content = new RandomValueStringGenerator(1024 * 4).generate();
        keyInfo = KeyInfoBuilder.build("valid", rsaSigningKey, "http://localhost/uaa");

        signedValidContent = JwtHelper.encode(content, keyInfo);

        validKey = new JsonWebKey(KeyInfoBuilder.build(null, rsaSigningKey, "http://localhost/uaa").getJwkMap());
        invalidKey = new JsonWebKey(KeyInfoBuilder.build(null, invalidRsaSigningKey, "http://localhost/uaa").getJwkMap());
    }

    @Test
    public void test_single_key_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Collections.singletonList(validKey)));
        signedValidContent.verifySignature(verifier);
    }

    @Test(expected = InvalidSignatureException.class)
    public void test_single_key_invalid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Collections.singletonList(invalidKey)));
        signedValidContent.verifySignature(verifier);
    }

    @Test
    public void test_multi_key_first_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(validKey, invalidKey)));
        signedValidContent.verifySignature(verifier);
    }

    @Test
    public void test_multi_key_last_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(invalidKey, validKey)));
        signedValidContent.verifySignature(verifier);
    }

    @Test(expected = InvalidSignatureException.class)
    public void test_multi_key_invalid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(invalidKey, invalidKey)));
        signedValidContent.verifySignature(verifier);
    }

    @Test
    public void check_that_we_use_common_signer() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", MAC.name());
        p.put("kid", "macid");
        p.put("value", "test-mac-key");
        JsonWebKey macKey = new JsonWebKey(p);
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(validKey, invalidKey, macKey)));
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(3, delegates.size());
        int pos = 0;
        for (SignatureVerifier v : delegates) {
            assertTrue("Checking " + (pos++), v instanceof CommonSignatureVerifier);
        }
    }

    @Test
    public void unsupported_key_types_are_ignored() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", "EC");
        p.put("kid", "ecid");
        p.put("x", "test-ec-key-x");
        p.put("y", "test-ec-key-y");
        p.put("use", "sig");
        p.put("crv", "test-crv");
        Map<String, Object> q = new HashMap<>();
        q.put("kty", "oct");
        q.put("k", "octkeyvalue");
        JsonWebKeySet keySet = JsonUtils.convertValue(singletonMap("keys", Arrays.asList(validKey, p, q)), JsonWebKeySet.class);
        verifier = new ChainedSignatureVerifier(keySet);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(1, delegates.size());
        int pos = 0;
        for (SignatureVerifier v : delegates) {
            assertTrue("Checking " + (pos++), v instanceof CommonSignatureVerifier);
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void no_supported_key_types_causes_error() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", "EC");
        p.put("kid", "ecid");
        p.put("x", "test-ec-key-x");
        p.put("y", "test-ec-key-y");
        p.put("use", "sig");
        p.put("crv", "test-crv");
        Map<String, Object> q = new HashMap<>();
        q.put("kty", "oct");
        q.put("k", "octkeyvalue");
        JsonWebKeySet keySet = JsonUtils.convertValue(singletonMap("keys", Arrays.asList(p, q)), JsonWebKeySet.class);
        verifier = new ChainedSignatureVerifier(keySet);
    }

    @Test
    public void test_multi_key_both_valid() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", MAC.name());
        p.put("value", "mac-content");
        JsonWebKey jsonWebKey = new JsonWebKey(p);

        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(validKey, jsonWebKey)));
        signedValidContent.verifySignature(verifier);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(2, delegates.size());
        assertEquals("HMACSHA256", delegates.get(1).algorithm());

        //ensure the second signer never gets invoked upon success
        delegates.remove(1);
        MacSigner macSigner = mock(MacSigner.class);
        delegates.add(macSigner);
        ReflectionTestUtils.setField(verifier, "delegates", delegates);
        signedValidContent.verifySignature(verifier);
        Mockito.verifyZeroInteractions(macSigner);
    }

}
