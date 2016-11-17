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

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class JsonWebKeySetTests {

    public static final String singleKeyJson = "{\n" +
        "    \"alg\": \"SHA256withRSA\",\n" +
        "    \"e\": \"AQAB\",\n" +
        "    \"kid\": \"legacy\",\n" +
        "    \"kty\": \"RSA\",\n" +
        "    \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "    \"use\": \"sig\",\n" +
        "    \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "}";

    public static final String multiKeyJson = "{\n" +
        "    \"keys\": [\n" +
        "        {\n" +
        "            \"alg\": \"SHA256withRSA\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"RSA\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        },\n" +
        "        {\n" +
        "            \"alg\": \"SHA256withRSA\",\n" +
        "            \"e\": \"AQAB\",\n" +
        "            \"kid\": \"legacy\",\n" +
        "            \"kty\": \"RSA\",\n" +
        "            \"n\": \"AMcWv4ogKaz625PU5cnCEJSZHZ0pXLumxrzHMSVLLOrHugnJ8nUlnI7NOiP1PlJ9Mirf3pqBsclZV9imE1qG9n_u4xeofF_5kf0EvWCT1jqQKdszlHrSB_CPJbX91A-M7Of03f3jN3YUmgUfB2r1CzTAG6CylQtlU1HGru96r9_P\",\n" +
        "            \"use\": \"sig\",\n" +
        "            \"value\": \"-----BEGIN PUBLIC KEY-----\\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\\nspULZVNRxq7veq/fzwIDAQAB\\n-----END PUBLIC KEY-----\"\n" +
        "        }\n" +
        "    ]\n" +
        "}";


    @Test
    public void test_multi_key() {
        test_key(multiKeyJson);
    }

    @Test
    public void test_single_key() {
        test_key(singleKeyJson);
    }

    public void test_key(String json) {
        JsonWebKeySet<JsonWebKey> keys = JsonWebKeySet.deserialize(json);
        assertNotNull(keys);
        assertNotNull(keys.getKeys());
        assertEquals(1, keys.getKeys().size());
        JsonWebKey key = keys.getKeys().get(0);
        assertEquals("SHA256withRSA", key.getAlgorithm());
        assertEquals(
            "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHFr+KICms+tuT1OXJwhCUmR2d\nKVy7psa8xzElSyzqx7oJyfJ1JZyOzToj9T5SfTIq396agbHJWVfYphNahvZ/7uMX\nqHxf+ZH9BL1gk9Y6kCnbM5R60gfwjyW1/dQPjOzn9N394zd2FJoFHwdq9Qs0wBug\nspULZVNRxq7veq/fzwIDAQAB\n-----END PUBLIC KEY-----",
            key.getValue()
        );
        assertEquals(sig, key.getUse());
    }

}
