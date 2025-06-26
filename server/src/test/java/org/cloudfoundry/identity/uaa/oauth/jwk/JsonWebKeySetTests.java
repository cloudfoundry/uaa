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

import com.nimbusds.jose.jwk.JWKSet;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;

class JsonWebKeySetTests {

    private static final String SINGLE_KEY_JSON = """
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "legacy",
                "kty": "RSA",
                "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                "use": "sig",
                "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
            }""";

    private static final String UNKNOWN_KEY_JSON = """
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "legacy",
                "kty": "GARBAGE",
                "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                "use": "sig",
                "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
            }""";

    private static final String MULTI_KEY_JSON = """
            {
                "keys": [
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "legacy",
                        "kty": "RSA",
                        "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                        "use": "sig",
                        "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
                    },
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "legacy",
                        "kty": "RSA",
                        "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                        "use": "sig",
                        "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
                    },
                    {
                        "alg": "HMACSHA256",
                        "k": "test-mac-key",
                        "kid": "mac-id",
                        "kty": "MAC",
                        "key_ops": ["sign","verify"]
                    },
                    {
                        "alg": "HS256",
                        "k": "test-oct-key",
                        "kid": "oct-id",
                        "kty": "oct",
                        "key_ops": ["verify"]
                    }
                ]
            }""";

    private static final String SOME_UNKNOWN_KEYS_JSON = """
            {
                "keys": [
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "legacy",
                        "kty": "RSA",
                        "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                        "use": "sig",
                        "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
                    },
                    {
                        "alg": "RS256",
                        "e": "AQAB",
                        "kid": "legacy",
                        "kty": "UNKNOWN1",
                        "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                        "use": "sig",
                        "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
                    },
                    {
                        "alg": "HMACSHA256",
                        "k": "test-mac-key",
                        "kid": "mac-id",
                        "kty": "UNKNOWN2",
                        "key_ops": ["sign","verify"]
                    }
                ]
            }""";

    @Test
    void multi_key() {
        JsonWebKeySet<JsonWebKey> keys = test_key(MULTI_KEY_JSON);
        assertThat(keys.getKeys()).hasSize(3);
        JsonWebKey key = keys.getKeys().get(1);
        assertThat(key.getAlgorithm()).isEqualTo("HMACSHA256");

        assertThat(key.getValue()).isEqualTo("test-mac-key");

        assertThat(key.getKeyProperties()).containsEntry("k", "test-mac-key");

        assertThat(key.getUse()).isNull();
        assertThat(key.getKeyOps()).isEqualTo(new LinkedHashSet<>(Arrays.asList(JsonWebKey.KeyOperation.sign, JsonWebKey.KeyOperation.verify)));
    }

    @Test
    void multi_key_rfc7518() {
        JsonWebKeySet<JsonWebKey> keys = test_key(MULTI_KEY_JSON);
        assertThat(keys.getKeys()).hasSize(3);
        JsonWebKey key = keys.getKeys().get(2);
        assertThat(key.getAlgorithm()).isEqualTo("HS256");

        assertThat(key.getValue()).isEqualTo("test-oct-key");

        assertThat(key.getKeyProperties()).containsEntry("k", "test-oct-key");

        assertThat(key.getUse()).isNull();
        assertThat(key.getKeyOps()).isEqualTo(new LinkedHashSet<>(List.of(JsonWebKey.KeyOperation.verify)));
    }

    @Test
    void single_key() {
        test_key(SINGLE_KEY_JSON);
    }

    public JsonWebKeySet<JsonWebKey> test_key(String json) {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(json);
        assertThat(keys).isNotNull();
        assertThat(keys.getKeys()).isNotNull();
        JsonWebKey key = keys.getKeys().getFirst();
        assertThat(key.getAlgorithm()).isEqualTo("RS256");
        assertThat(key.getValue()).isEqualTo("-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\nspULZVNRxq7veq/fzwIDAQAB\n-----END PUBLIC KEY-----");
        assertThat(key.getUse()).isEqualTo(sig);
        return keys;
    }

    @Test
    void unknownKeyType() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(UNKNOWN_KEY_JSON);
        assertThat(keys.getKeys()).isEmpty();
    }

    @Test
    void ignoreUnknownKeyTypes() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(SOME_UNKNOWN_KEYS_JSON);
        assertThat(keys.getKeys()).hasSize(1);
    }

    @Test
    void jsonKeySetParseJson() throws ParseException {
        String jsonConfig = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"xMi4Z4FBfQEOdNYLmzxkYJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9JCJP2IWbHJ4sRe0S1dySYdBRVV_ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp-ugeGoxK-fsk8SRLS_Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMckrEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1wvdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF_PkA88NkjN2-W9fQmbUzNgVjEQiXo4w\"}]}";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(jsonConfig);
        assertThat(keys.getKeys()).hasSize(1);
        assertThat(keys.getKeySetMap()).hasSize(1);
        JWKSet joseSet = JWKSet.parse(keys.getKeySetMap());
        assertThat(joseSet).isNotNull();
        assertThat(joseSet.size()).isOne();
    }

    @Test
    void jsonKeySetParsePublicKey() throws ParseException {
        String publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4FBfQEOdNYLmzxkYJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9JCJP2IWbHJ4sRe0S1dySYdBRVV/ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp+ugeGoxK+fsk8SRLS/Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMckrEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1wvdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF/PkA88NkjN2+W9fQmbUzNgVjEQiXo4wIDAQAB-----END PUBLIC KEY-----";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(publicKey);
        assertThat(keys.getKeys()).hasSize(1);
        assertThat(keys.getKeySetMap()).hasSize(1);
        JWKSet joseSet = JWKSet.parse(keys.getKeySetMap());
        assertThat(joseSet).isNotNull();
        assertThat(joseSet.size()).isOne();
    }

    @Test
    void jsonKeySetParseFailurePEM() {
        String publicKey = "-----BEGIN PUBLIC KEY-----tokenKey-----END PUBLIC KEY-----";
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> JsonWebKeyHelper.parseConfiguration(publicKey));
    }

    @Test
    void jsonKeySetParseRawKey() {
        String macKey = "tokenKey";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(macKey);
        assertThat(keys.getKeys()).hasSize(1);
        assertThat(keys.getKeys().getFirst().getKty()).isEqualTo(JsonWebKey.KeyType.MAC);
        assertThat(keys.getKeys().getFirst().getValue()).isEqualTo(macKey);
    }
}
