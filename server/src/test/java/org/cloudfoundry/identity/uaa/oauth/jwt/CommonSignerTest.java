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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.DEFAULT_UAA_URL;

class CommonSignerTest {
    private String rsaSigningKey;
    private String macSigningKey;

    @BeforeEach
    void setup() {
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
    void rsa_key_null_id() {
        CommonSigner signer = new CommonSigner(null, rsaSigningKey, "http://localhost/uaa");
        assertThat(signer.algorithm()).isEqualTo("RS256");
        assertThat(signer.keyId()).isNull();
    }

    @Test
    void rsa_key_with_id() {
        CommonSigner signer = new CommonSigner("id", rsaSigningKey, "http://localhost/uaa");
        assertThat(signer.algorithm()).isEqualTo("RS256");
        assertThat(signer.keyId()).isEqualTo("id");
    }

    @Test
    void mac_key_null_id() {
        CommonSigner signer = new CommonSigner(null, macSigningKey, "http://localhost/uaa");
        assertThat(signer.algorithm()).isEqualTo("HS256");
        assertThat(signer.keyId()).isNull();
    }

    @Test
    void mac_key_with_id() {
        CommonSigner signer = new CommonSigner("id", macSigningKey, "http://localhost/uaa");
        assertThat(signer.algorithm()).isEqualTo("HS256");
        assertThat(signer.keyId()).isEqualTo("id");
        assertThat(signer.keyURL()).isEqualTo("http://localhost/uaa");
    }

    @Test
    void null_key_is_rejected() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> {
            new CommonSigner("id", null, "http://localhost/uaa");
        });
    }

    @Test
    void mac_signing() throws JOSEException, ParseException {
        final String jwtFromIo = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJzdWIiOiIxMjM0NTY3ODkwIn0.hUTNPTwAP4RQFr_d_GOwXrVOJsX1-PWAvHSsg-CSQPk";
        CommonSigner signer = new CommonSigner(null, macSigningKey, DEFAULT_UAA_URL);
        assertThat(signer.algorithm()).isEqualTo("HS256");
        assertThat(signer.keyId()).isNull();
        SignedJWT inJwt = SignedJWT.parse(jwtFromIo);
        Base64URL jwt = signer.sign(inJwt.getHeader(), inJwt.getSigningInput());
        assertThat(jwt).isEqualTo(inJwt.getSignature());
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build();
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("1234567890").claim("name", "John Doe").build();
        Base64URL signature = signer.sign(header, new SignedJWT(header, claimsSet).getSigningInput());
        assertThat(signature).isEqualTo(inJwt.getSignature());
        UaaMacSigner uaaMacSigner = new UaaMacSigner(macSigningKey);
        assertThat(uaaMacSigner.getSecret()).hasSameSizeAs(new SecretKeySpec(macSigningKey.getBytes(StandardCharsets.UTF_8), "HS256").getEncoded());
    }

    @Test
    void mac_signing_options() {
        CommonSigner signer = new CommonSigner(null, macSigningKey, "http://localhost/uaa");
        assertThat(signer.supportedJWSAlgorithms()).isEqualTo(UaaMacSigner.SUPPORTED_ALGORITHMS);
        assertThat(signer.getJCAContext()).isNotNull();
    }

    @Test
    void nimbus_singing_with_single_aud_value() throws JOSEException, ParseException {
        // given
        Map<String, Object> objectMap = Map.of("sub", "1234567890", "name", "John Doe", "aud", List.of("single"));
        // when
        CommonSigner signer = new CommonSigner("id", rsaSigningKey, "http://localhost/uaa");
        assertThat(signer.algorithm()).isEqualTo("RS256");
        assertThat(signer.keyId()).isEqualTo("id");
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build();
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(objectMap);
        SignedJWT resultedJwt = new SignedJWT(header, claimsSet);
        resultedJwt.sign(signer);
        String payLoadString = JWTParser.parse(resultedJwt.serialize()).getParsedParts()[1].decodeToString();
        // then
        assertThat(payLoadString).contains("\"aud\":\"single\"");
    }

    @Test
    void uaa_singing_with_single_aud_value() throws ParseException {
        // given
        Map<String, Object> objectMap = Map.of("sub", "1234567890", "name", "John Doe", "aud", List.of("single"));
        // when
        String uaaResultedJwt = JwtHelper.encode(objectMap, KeyInfoBuilder.build("id", rsaSigningKey, "http://localhost/uaa")).getEncoded();
        String payLoadString = JWTParser.parse(uaaResultedJwt).getParsedParts()[1].decodeToString();
        // then
        assertThat(payLoadString).contains("\"aud\":[\"single\"]");
    }
}
