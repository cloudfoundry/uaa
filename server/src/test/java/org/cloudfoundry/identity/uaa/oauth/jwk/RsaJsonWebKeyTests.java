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

package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.BigIntegerUtils;
import org.apache.commons.collections4.map.HashedMap;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.token.VerificationKeyResponse;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.RSA;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;
import static org.cloudfoundry.identity.uaa.oauth.jwk.RsaJsonWebKeyTestUtils.SAMPLE_RSA_KEYS;
import static org.cloudfoundry.identity.uaa.oauth.jwk.RsaJsonWebKeyTestUtils.SAMPLE_RSA_PRIVATE_KEY;
import static org.cloudfoundry.identity.uaa.oauth.jwk.RsaJsonWebKeyTestUtils.parseKeyPair;

public class RsaJsonWebKeyTests {
    private static final String ISSUER = "http://localhost:8080/issuer";

    @Test
    void create_key_from_pem_string() {
        KeyInfo keyInfo = KeyInfoBuilder.build("id", SAMPLE_RSA_PRIVATE_KEY, ISSUER);
        assertThat(keyInfo.type()).isEqualTo("RSA");
        assertThat(keyInfo.getVerifier()).isNotNull();

        JsonWebKey key = new JsonWebKey(KeyInfoBuilder.build("id", SAMPLE_RSA_PRIVATE_KEY, ISSUER).getJwkMap()).setKid("id");

        assertThat(key.getKty()).isEqualTo(RSA);
        assertThat(key.getKeyProperties()).containsEntry("kty", "RSA");
        assertThat(key.getKid()).isEqualTo("id");
        assertThat(key.getUse()).isEqualTo(sig);
        assertThat(key.getKeyProperties()).containsEntry("use", "sig");
        assertThat(key.getValue()).isNotNull();

        PublicKey pk = parseKeyPair(keyInfo.verifierKey()).getPublic();

        BigInteger exponent = ((RSAPublicKey) pk).getPublicExponent();
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();
        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        assertThat(key.getKeyProperties()).containsEntry("e", encoder.encodeToString(exponent.toByteArray())).containsEntry("n", encoder.encodeToString(BigIntegerUtils.toBytesUnsigned(modulus)));
    }

    @Test
    void create_key_from_public_pem_string() {
        KeyInfo keyInfo = KeyInfoBuilder.build("id", SAMPLE_RSA_PRIVATE_KEY, ISSUER);
        assertThat(keyInfo.type()).isEqualTo("RSA");
        assertThat(keyInfo.getVerifier()).isNotNull();

        Map<String, Object> jwkMap = keyInfo.getJwkMap();
        JsonWebKey jsonWebKey = new JsonWebKey(jwkMap);
        JsonWebKey key = jsonWebKey.setKid("id");
        assertThat(key.getKty()).isEqualTo(RSA);
        assertThat(key.getKeyProperties()).containsEntry("kty", "RSA");
        assertThat(key.getKid()).isEqualTo("id");
        assertThat(key.getUse()).isEqualTo(sig);
        assertThat(key.getKeyProperties()).containsEntry("use", "sig");
        assertThat(key.getValue()).isNotNull();

        PublicKey pk = parseKeyPair(keyInfo.verifierKey()).getPublic();
        BigInteger exponent = ((RSAPublicKey) pk).getPublicExponent();
        BigInteger modulus = ((RSAPublicKey) pk).getModulus();

        java.util.Base64.Encoder encoder = java.util.Base64.getUrlEncoder().withoutPadding();
        assertThat(key.getKeyProperties()).containsEntry("e", encoder.encodeToString(exponent.toByteArray())).containsEntry("n", encoder.encodeToString(BigIntegerUtils.toBytesUnsigned(modulus)));
    }

    @Test
    void deserialize_azure_keys() {
        deserialize_azure_keys(SAMPLE_RSA_KEYS);
    }

    @Test
    void ensure_that_duplicates_are_removed() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(SAMPLE_RSA_KEYS, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        List<JsonWebKey> list = new ArrayList<>(keys.getKeys());
        list.addAll(keys.getKeys());
        assertThat(list).hasSize(6);
        keys = new JsonWebKeySet<>(list);
        deserialize_azure_keys(JsonUtils.writeValueAsString(keys));
    }

    @Test
    void ensure_that_duplicates_get_the_last_object() {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(SAMPLE_RSA_KEYS, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        List<JsonWebKey> list = new ArrayList<>(keys.getKeys());
        list.addAll(keys.getKeys());
        assertThat(list).hasSize(6);

        Map<String, Object> p = new HashedMap<>(list.get(5).getKeyProperties());
        p.put("issuer", ISSUER);
        list.add(new VerificationKeyResponse(p));
        assertThat(list).hasSize(7);

        keys = new JsonWebKeySet<>(list);
        keys = deserialize_azure_keys(JsonUtils.writeValueAsString(keys));

        assertThat(keys.getKeys().get(2).getKeyProperties()).containsEntry("issuer", ISSUER);
    }

    @Test
    void required_properties() {
        Map<String, Object> map = new HashMap<>();
        test_create_with_error(map);
        map.put("kty", "RSA");
        new VerificationKeyResponse(map);
    }

    @Test
    void equals() {
        Map<String, Object> p1 = new HashMap<>();
        p1.put("kty", "RSA");
        Map<String, Object> p2 = new HashMap<>(p1);
        assertThat(new VerificationKeyResponse(p2)).isEqualTo(new VerificationKeyResponse(p1));
        p1.put("kid", "id");
        assertThat(new VerificationKeyResponse(p2)).isNotEqualTo(new VerificationKeyResponse(p1));
        p2.put("kid", "id");
        assertThat(new VerificationKeyResponse(p2)).isEqualTo(new VerificationKeyResponse(p1));
        p1.put("issuer", "issuer1");
        p2.put("issuer", "issuer2");
        assertThat(new VerificationKeyResponse(p2)).isEqualTo(new VerificationKeyResponse(p1));
        p1.remove("kid");
        p2.remove("kid");
        assertThat(new VerificationKeyResponse(p2)).isNotEqualTo(new VerificationKeyResponse(p1));
        p2.put("issuer", "issuer1");
        assertThat(new VerificationKeyResponse(p2)).isEqualTo(new VerificationKeyResponse(p1));
    }

    private void test_create_with_error(Map p) {
        assertThatThrownBy(() -> new VerificationKeyResponse(p))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private JsonWebKeySet<JsonWebKey> deserialize_azure_keys(String json) {
        JsonWebKeySet<JsonWebKey> keys = JsonUtils.readValue(json, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
        });
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).hasSize(3);
        for (JsonWebKey key : keys.getKeys()) {
            assertThat(key).isNotNull();
            assertThat(JsonWebKey.getRsaPublicKey(key)).isNotNull();
        }
        return keys;
    }

    // see https://github.com/cloudfoundry/uaa/issues/1514
    private static final String ISSUE_1514_KEY = "-----BEGIN PUBLIC KEY-----\\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyH6kYCP29faDAUPKtei3\\n" +
            "V/Zh8eCHyHRDHrD0iosvgHuaakK1AFHjD19ojuPiTQm8r8nEeQtHb6mDi1LvZ03e\\n" +
            "EWxpvWwFfFVtCyBqWr5wn6IkY+ZFXfERLn2NCn6sMVxcFV12sUtuqD+jrW8MnTG7\\n" +
            "hofQqxmVVKKsZiXCvUSzfiKxDgoiRuD3MJSoZ0nQTHVmYxlFHuhTEETuTqSPmOXd\\n" +
            "/xJBVRi5WYCjt1aKRRZEz04zVEBVhVkr2H84qcVJHcfXFu4JM6dg0nmTjgd5cZUN\\n" +
            "cwA1KhK2/Qru9N0xlk9FGD2cvrVCCPWFPvZ1W7U7PBWOSBBH6GergA+dk2vQr7Ho\\n" +
            "lQIDAQAB\\n" +
            "-----END PUBLIC KEY-----";

    public static final String ISSUE_1514_KEY_JSON = """
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "legacy",
                "kty": "RSA",
                "n": "yH6kYCP29faDAUPKtei3V_Zh8eCHyHRDHrD0iosvgHuaakK1AFHjD19ojuPiTQm8r8nEeQtHb6mDi1LvZ03eEWxpvWwFfFVtCyBqWr5wn6IkY-ZFXfERLn2NCn6sMVxcFV12sUtuqD-jrW8MnTG7hofQqxmVVKKsZiXCvUSzfiKxDgoiRuD3MJSoZ0nQTHVmYxlFHuhTEETuTqSPmOXd_xJBVRi5WYCjt1aKRRZEz04zVEBVhVkr2H84qcVJHcfXFu4JM6dg0nmTjgd5cZUNcwA1KhK2_Qru9N0xlk9FGD2cvrVCCPWFPvZ1W7U7PBWOSBBH6GergA-dk2vQr7HolQ",
                "use": "sig",
                "value": "%s"
            }""".formatted(ISSUE_1514_KEY);

    @Test
    void jwt_key_encoding() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(ISSUE_1514_KEY_JSON);
        PublicKey pk = parseKeyPair(ISSUE_1514_KEY.replace("\\n", "\n")).getPublic();
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).isNotNull();
        JsonWebKey key = keys.getKeys().getFirst();
        assertThat(Base64URL.encode(((RSAPublicKey) pk).getModulus())).hasToString((String) key.getKeyProperties().get("n"));
    }
}
