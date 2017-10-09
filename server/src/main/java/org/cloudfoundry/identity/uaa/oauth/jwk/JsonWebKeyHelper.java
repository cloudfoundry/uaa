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
import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyUse.sig;


public class JsonWebKeyHelper {
    private static Base64 base64 = new Base64(true);

    public static JsonWebKey fromPEMPrivateKey(String key) {
        KeyPair pair = KeyInfo.parseKeyPair(key);
        RSAPublicKey rsaKey = (RSAPublicKey) pair.getPublic();
        BigInteger modulus = rsaKey.getModulus();
        BigInteger exponent = rsaKey.getPublicExponent();
        Map<String, Object> properties = new HashMap();
        properties.put("n", base64.encodeAsString(modulus.toByteArray()));
        properties.put("e", base64.encodeAsString(exponent.toByteArray()));
        properties.put("kty", "RSA");
        properties.put("use", sig.name());
        properties.put("value", KeyInfo.pemEncodePublicKey(rsaKey));
        return new JsonWebKey(properties);
    }

    public static JsonWebKey fromPEMPublicKey(String key) {
        return fromPEMPrivateKey(key);
    }

    public static JsonWebKeySet<JsonWebKey> deserialize(String s) {
        if (!s.contains("\"keys\"")) {
            return new JsonWebKeySet<>(Arrays.asList(JsonUtils.readValue(s, JsonWebKey.class)));
        } else {
            return JsonUtils.readValue(s, new TypeReference<JsonWebKeySet<JsonWebKey>>() {});
        }
    }

    public static JsonWebKeySet<JsonWebKey> fromResultMaps(List<Map<String, Object>> resultMaps) {
        return new JsonWebKeySet<>(resultMaps.stream().map(JsonWebKey::new).collect(Collectors.toList()));
    }
}
