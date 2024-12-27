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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class CommonSignerTest {
    private String rsaSigningKey;
    private String macSigningKey;

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
        macSigningKey = "mac-sign-key";
    }

    @Test
    public void test_rsa_key_null_id() {
        CommonSigner signer = new CommonSigner(null, rsaSigningKey, "http://localhost/uaa");
        assertEquals("RS256", signer.algorithm());
        assertNull(signer.keyId());
    }

    @Test
    public void test_rsa_key_with_id() {
        CommonSigner signer = new CommonSigner("id", rsaSigningKey, "http://localhost/uaa");
        assertEquals("RS256", signer.algorithm());
        assertEquals("id", signer.keyId());
    }

    @Test
    public void test_mac_key_null_id() {
        CommonSigner signer = new CommonSigner(null, macSigningKey, "http://localhost/uaa");
        assertEquals("HS256", signer.algorithm());
        assertNull(signer.keyId());
    }

    @Test
    public void test_mac_key_with_id() {
        CommonSigner signer = new CommonSigner("id", macSigningKey, "http://localhost/uaa");
        assertEquals("HS256", signer.algorithm());
        assertEquals("id", signer.keyId());
        assertEquals("http://localhost/uaa", signer.keyURL());
    }

    @Test(expected = IllegalArgumentException.class)
    public void null_key_is_rejected() {
        new CommonSigner("id", null, "http://localhost/uaa");
    }

    @Test
    public void test_mac_signing() throws JOSEException, ParseException {
        final String jwtFromIo = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.hUTNPTwAP4RQFr_d_GOwXrVOJsX1-PWAvHSsg-CSQPk";
        CommonSigner signer = new CommonSigner(null, macSigningKey, DEFAULT_UAA_URL);
        assertEquals("HS256", signer.algorithm());
        assertNull(signer.keyId());
        SignedJWT inJwt = SignedJWT.parse(jwtFromIo);
        Base64URL jwt = signer.sign(inJwt.getHeader(), inJwt.getSigningInput());
        assertEquals(inJwt.getSignature(), jwt);
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("1234567890").claim("name", "John Doe").build();
        Base64URL signature = signer.sign(header, new SignedJWT(header, claimsSet).getSigningInput());
        assertEquals(inJwt.getSignature(), signature);
        UaaMacSigner uaaMacSigner = new UaaMacSigner(macSigningKey);
        assertEquals(new SecretKeySpec(macSigningKey.getBytes(StandardCharsets.UTF_8), "HS256").getEncoded().length, uaaMacSigner.getSecret().length);
    }

    @Test
    public void test_mac_signing_options() {
        CommonSigner signer = new CommonSigner(null, macSigningKey, "http://localhost/uaa");
        assertEquals(UaaMacSigner.SUPPORTED_ALGORITHMS, signer.supportedJWSAlgorithms());
        assertNotNull(signer.getJCAContext());
    }

    @Test
    public void test_nimbus_singing_with_single_aud_value() throws JOSEException, ParseException {
        // given
        Map<String, Object> objectMap = Map.of("sub", "1234567890", "name", "John Doe", "aud", Arrays.asList("single"));
        // when
        CommonSigner signer = new CommonSigner("id", rsaSigningKey, "http://localhost/uaa");
        assertEquals("RS256", signer.algorithm());
        assertEquals("id", signer.keyId());
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(objectMap);
        SignedJWT resultedJwt = new SignedJWT(header, claimsSet);
        resultedJwt.sign(signer);
        String payLoadString = JWTParser.parse(resultedJwt.serialize()).getParsedParts()[1].decodeToString();
        // then
        assertThat(payLoadString, Matchers.containsString("\"aud\":\"single\""));
    }

    @Test
    public void test_uaa_singing_with_single_aud_value() throws ParseException {
        // given
        Map<String, Object> objectMap = Map.of("sub", "1234567890", "name", "John Doe", "aud", Arrays.asList("single"));
        // when
        String uaaResultedJwt = JwtHelper.encode(objectMap, KeyInfoBuilder.build("id", rsaSigningKey, "http://localhost/uaa")).getEncoded();
        String payLoadString = JWTParser.parse(uaaResultedJwt).getParsedParts()[1].decodeToString();
        // then
        assertThat(payLoadString, Matchers.containsString("\"aud\":[\"single\"]"));
    }
}
