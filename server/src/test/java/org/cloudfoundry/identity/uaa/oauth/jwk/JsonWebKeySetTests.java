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

import org.junit.Test;

import java.util.Arrays;
import java.util.LinkedHashSet;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class JsonWebKeySetTests {

    public static final String singleKeyJson = "{\n" +
        "    \"alg\": \"RS256\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"kid\": \"legacy\",\n" +
        "    \"kty\": \"RSA\",\n" +
        "    \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "}";

    public static final String unknownKeyJson = "{\n" +
        "    \"alg\": \"RS256\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"kid\": \"legacy\",\n" +
        "    \"kty\": \"GARBAGE\",\n" +
        "    \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "}";

    public static final String multiKeyJson = "{\n" +
        "    \"keys\": [\n" +
        "        {\n" +
        "            \"alg\": \"RS256\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"RSA\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        },\n" +
        "        {\n" +
        "            \"alg\": \"RS256\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"RSA\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        },\n" +
        "        {\n" +
        "            \"alg\": \"HMACSHA256\",\n" +
        "            \"k\": \"test-mac-key\",\n" +
        "            \"kid\": \"mac-id\",\n" +
        "            \"kty\": \"MAC\",\n" +
        "            \"key_ops\": [\"sign\",\"verify\"]\n" +
        "        }\n" +
        "    ]\n" +
        "}";

    public static final String someUnknownKeysJson = "{\n" +
        "    \"keys\": [\n" +
        "        {\n" +
        "            \"alg\": \"RS256\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"RSA\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        },\n" +
        "        {\n" +
        "            \"alg\": \"RS256\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"UNKNOWN1\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        },\n" +
        "        {\n" +
        "            \"alg\": \"HMACSHA256\",\n" +
        "            \"k\": \"test-mac-key\",\n" +
        "            \"kid\": \"mac-id\",\n" +
        "            \"kty\": \"UNKNOWN2\",\n" +
        "            \"key_ops\": [\"sign\",\"verify\"]\n" +
        "        }\n" +
        "    ]\n" +
        "}";


    @Test
    public void test_multi_key() {
        JsonWebKeySet<JsonWebKey> keys = test_key(multiKeyJson);
        assertEquals(2, keys.getKeys().size());
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

}
