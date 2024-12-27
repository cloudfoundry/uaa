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

import org.cloudfoundry.identity.uaa.oauth.InvalidSignatureException;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKeySet;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
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
        rsaSigningKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T
                PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo
                hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB
                AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA
                BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj
                RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3
                2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=
                -----END RSA PRIVATE KEY-----""";

        invalidRsaSigningKey = """
                -----BEGIN RSA PRIVATE KEY-----
                MIIBOgIBAAJBAJnlBG4lLmUiHslsKDODfd0MqmGZRNUOhn7eO3cKobsFljUKzRQe
                GB7LYMjPavnKccm6+jWSXutpzfAc9A9wXG8CAwEAAQJADwwdiseH6cuURw2UQLUy
                sVJztmdOG6b375+7IMChX6/cgoF0roCPP0Xr70y1J4TXvFhjcwTgm4RI+AUiIDKw
                gQIhAPQHwHzdYG1639Qz/TCHzuai0ItwVC1wlqKpat+CaqdZAiEAoXFyS7249mRu
                xtwRAvxKMe+eshHvG2le+ZDrM/pz8QcCIQCzmCDpxGL7L7sbCUgFN23l/11Lwdex
                uXKjM9wbsnebwQIgeZIbVovUp74zaQ44xT3EhVwC7ebxXnv3qAkIBMk526sCIDVg
                z1jr3KEcaq9zjNJd9sKBkqpkVSqj8Mv+Amq+YjBA
                -----END RSA PRIVATE KEY-----""";

        invalidSigner = new CommonSigner("invalid", invalidRsaSigningKey, "http://localhost/uaa");

        content = "{\"sub\": \"" + new RandomValueStringGenerator(1024 * 4).generate() + "\"}";
        keyInfo = KeyInfoBuilder.build("valid", rsaSigningKey, "http://localhost/uaa");

        signedValidContent = JwtHelper.encode(JsonUtils.readValue(content, HashMap.class), keyInfo);

        validKey = new JsonWebKey(KeyInfoBuilder.build(null, rsaSigningKey, "http://localhost/uaa").getJwkMap());
        invalidKey = new JsonWebKey(KeyInfoBuilder.build(null, invalidRsaSigningKey, "http://localhost/uaa").getJwkMap());
    }

    @Test
    public void test_single_key_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Collections.singletonList(validKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
    }

    @Test(expected = InvalidSignatureException.class)
    public void test_single_key_invalid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Collections.singletonList(invalidKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
    }

    @Test
    public void test_multi_key_first_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(validKey, invalidKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
    }

    @Test
    public void test_multi_key_last_valid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(invalidKey, validKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
    }

    @Test(expected = InvalidSignatureException.class)
    public void test_multi_key_invalid() {
        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(invalidKey, invalidKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
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
            assertTrue("Checking " + (pos++), v instanceof SignatureVerifier);
        }
    }

    @Test
    public void unsupported_key_types_are_ignored() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", "ES");
        p.put("kid", "ecid");
        p.put("x", "test-ec-key-x");
        p.put("y", "test-ec-key-y");
        p.put("use", "sig");
        p.put("crv", "test-crv");
        Map<String, Object> q = new HashMap<>();
        q.put("kty", "MC");
        q.put("k", "octkeyvalue");
        JsonWebKeySet keySet = JsonUtils.convertValue(singletonMap("keys", Arrays.asList(validKey, p, q)), JsonWebKeySet.class);
        verifier = new ChainedSignatureVerifier(keySet);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(1, delegates.size());
        int pos = 0;
        for (SignatureVerifier v : delegates) {
            assertTrue("Checking " + (pos++), v instanceof SignatureVerifier);
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
    public void test_single_hmackey_valid() {
        Map<String, Object> q = new HashMap<>();
        q.put("kid", "test");
        q.put("kty", "oct");
        q.put("k", "octkeyvalue");
        JsonWebKeySet keySet = JsonUtils.convertValue(singletonMap("keys", Arrays.asList(q)), JsonWebKeySet.class);
        verifier = new ChainedSignatureVerifier(keySet);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(1, delegates.size());
        assertEquals("HS256", delegates.get(0).algorithm());
    }

    @Test
    public void test_single_eckey_valid() {
        Map<String, Object> q = new HashMap<>();
        q.put("kid", "ec-key");
        q.put("kty", "EC");
        q.put("crv", "P-256");
        q.put("x", "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0");
        q.put("y", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps");
        JsonWebKeySet keySet = JsonUtils.convertValue(singletonMap("keys", Arrays.asList(q)), JsonWebKeySet.class);
        verifier = new ChainedSignatureVerifier(keySet);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(1, delegates.size());
        assertNotNull(delegates.get(0));
        assertEquals("ES256", delegates.get(0).algorithm());
    }

    @Test
    public void test_multi_key_both_valid() {
        Map<String, Object> p = new HashMap<>();
        p.put("kty", MAC.name());
        p.put("value", "mac-content");
        JsonWebKey jsonWebKey = new JsonWebKey(p);

        verifier = new ChainedSignatureVerifier(new JsonWebKeySet<>(Arrays.asList(validKey, jsonWebKey)));
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
        List<SignatureVerifier> delegates = new ArrayList((List<SignatureVerifier>) ReflectionTestUtils.getField(verifier, verifier.getClass(), "delegates"));
        assertNotNull(delegates);
        assertEquals(2, delegates.size());
        assertEquals("HS256", delegates.get(1).algorithm());

        //ensure the second signer never gets invoked upon success
        delegates.remove(1);
        SignatureVerifier macSigner = mock(SignatureVerifier.class);
        delegates.add(macSigner);
        ReflectionTestUtils.setField(verifier, "delegates", delegates);
        JwtHelper.decode(signedValidContent.getEncoded()).verifySignature(verifier);
        Mockito.verifyNoInteractions(macSigner);
    }

}
