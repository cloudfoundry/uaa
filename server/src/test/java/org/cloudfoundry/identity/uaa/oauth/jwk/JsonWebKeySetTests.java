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
import org.junit.Test;

import java.text.ParseException;
import java.util.Arrays;
import java.util.LinkedHashSet;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

public class JsonWebKeySetTests {

    public static final String singleKeyJson = """
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "legacy",
                "kty": "RSA",
                "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                "use": "sig",
                "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
            }\
            """;

    public static final String unknownKeyJson = """
            {
                "alg": "RS256",
                "e": "AQAB",
                "kid": "legacy",
                "kty": "GARBAGE",
                "n": "AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P",
                "use": "sig",
                "value": "-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----"
            }\
            """;

    public static final String multiKeyJson = """
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
            }\
            """;

    public static final String someUnknownKeysJson = """
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
            }\
            """;


    @Test
    public void test_multi_key() {
        JsonWebKeySet<JsonWebKey> keys = test_key(multiKeyJson);
        assertEquals(3, keys.getKeys().size());
        JsonWebKey key = keys.getKeys().get(1);
        assertEquals("HMACSHA256", key.getAlgorithm());

        assertEquals(
                "test-mac-key",
                key.getValue()
        );

        assertEquals(
                "test-mac-key",
                key.getKeyProperties().get("k")
        );

        assertNull(key.getUse());
        assertEquals(new LinkedHashSet<>(Arrays.asList(JsonWebKey.KeyOperation.sign, JsonWebKey.KeyOperation.verify)), key.getKeyOps());
    }

    @Test
    public void test_multi_key_rfc7518() {
        JsonWebKeySet<JsonWebKey> keys = test_key(multiKeyJson);
        assertEquals(3, keys.getKeys().size());
        JsonWebKey key = keys.getKeys().get(2);
        assertEquals("HS256", key.getAlgorithm());

        assertEquals(
                "test-oct-key",
                key.getValue()
        );

        assertEquals(
                "test-oct-key",
                key.getKeyProperties().get("k")
        );

        assertNull(key.getUse());
        assertEquals(new LinkedHashSet<>(Arrays.asList(JsonWebKey.KeyOperation.verify)), key.getKeyOps());
    }

    @Test
    public void test_single_key() {
        test_key(singleKeyJson);
    }

    public JsonWebKeySet<JsonWebKey> test_key(String json) {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(json);
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        JsonWebKey key = keys.getKeys().get(0);
        assertEquals("RS256", key.getAlgorithm());
        assertEquals(
                "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\nspULZVNRxq7veq/fzwIDAQAB\n-----END PUBLIC KEY-----",
                key.getValue()
        );
        assertEquals(sig, key.getUse());
        return keys;
    }

    @Test
    public void testUnknownKeyType() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(unknownKeyJson);
        assertEquals(0, keys.getKeys().size());
    }

    @Test
    public void testIgnoreUnknownKeyTypes() {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.deserialize(someUnknownKeysJson);
        assertEquals(1, keys.getKeys().size());
    }

    @Test
    public void testJsonKeySetParseJson() throws ParseException {
        String jsonConfig = "{\"keys\":[{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"key-1\",\"alg\":\"RS256\",\"n\":\"xMi4Z4FBfQEOdNYLmzxkYJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9JCJP2IWbHJ4sRe0S1dySYdBRVV_ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp-ugeGoxK-fsk8SRLS_Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMckrEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1wvdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF_PkA88NkjN2-W9fQmbUzNgVjEQiXo4w\"}]}";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(jsonConfig);
        assertEquals(1, keys.getKeys().size());
        assertEquals(1, keys.getKeySetMap().size());
        JWKSet joseSet = JWKSet.parse(keys.getKeySetMap());
        assertNotNull(joseSet);
        assertEquals(1, joseSet.size());
    }

    @Test
    public void testJsonKeySetParsePublicKey() throws ParseException {
        String publicKey = "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4FBfQEOdNYLmzxkYJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9JCJP2IWbHJ4sRe0S1dySYdBRVV/ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp+ugeGoxK+fsk8SRLS/Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMckrEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1wvdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF/PkA88NkjN2+W9fQmbUzNgVjEQiXo4wIDAQAB-----END PUBLIC KEY-----";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(publicKey);
        assertEquals(1, keys.getKeys().size());
        assertEquals(1, keys.getKeySetMap().size());
        JWKSet joseSet = JWKSet.parse(keys.getKeySetMap());
        assertNotNull(joseSet);
        assertEquals(1, joseSet.size());
    }

    @Test
    public void testJsonKeySetParseFailurePEM() throws ParseException {
        String publicKey = "-----BEGIN PUBLIC KEY-----tokenKey-----END PUBLIC KEY-----";
        assertThrows(IllegalArgumentException.class, () -> JsonWebKeyHelper.parseConfiguration(publicKey));
    }

    @Test
    public void testJsonKeySetParseRawKey() {
        String macKey = "tokenKey";
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeyHelper.parseConfiguration(macKey);
        assertEquals(1, keys.getKeys().size());
        assertEquals(JsonWebKey.KeyType.MAC, keys.getKeys().get(0).getKty());
        assertEquals(macKey, keys.getKeys().get(0).getValue());
    }
}
