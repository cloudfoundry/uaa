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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey.KeyType.MAC;

public final class JsonWebKeyHelper {
    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
    private static final Pattern WS_DATA = Pattern.compile("\\s", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern JSON_DATA = Pattern.compile("^\\{(.*)\\:(.*)\\}$", Pattern.DOTALL);
    private static final int PEM_TYPE = 1;
    private static final int PEM_CONTENT = 2;

    private JsonWebKeyHelper() {
    }

    public static JsonWebKeySet<JsonWebKey> deserialize(String s) {
        if (!s.contains("\"keys\"")) {
            return new JsonWebKeySet<>(Collections.singletonList(JsonUtils.readValue(s, JsonWebKey.class)));
        } else {
            return JsonUtils.readValue(s, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
            });
        }
    }

    public static JWK getJsonWebKey(String pemData) throws JOSEException {
        Matcher m = PEM_DATA.matcher(pemData.trim());
        if (!m.matches()) {
            throw new IllegalArgumentException("String is not PEM encoded data");
        }
        String begin = "-----BEGIN " + m.group(PEM_TYPE) + "-----\n";
        String end = "\n-----END " + m.group(PEM_TYPE) + "-----";
        return JWK.parseFromPEMEncodedObjects(begin + WS_DATA.matcher(m.group(PEM_CONTENT).trim()).replaceAll("\n") + end);
    }

    public static JsonWebKeySet<JsonWebKey> parseConfiguration(String tokenKey) {
        Matcher m = JSON_DATA.matcher(tokenKey.trim());
        if (m.matches()) {
            return deserialize(tokenKey);
        } else {
            try {
                if (PEM_DATA.matcher(tokenKey.trim()).matches()) {
                    return deserialize(getJsonWebKey(tokenKey).toJSONString());
                } else {
                    Map<String, Object> p = new HashMap<>();
                    p.put("value", tokenKey);
                    p.put("kty", MAC.name());
                    return new JsonWebKeySet<>(Collections.singletonList(new JsonWebKey(p)));
                }
            } catch (JOSEException e) {
                throw new IllegalArgumentException(e);
            }
        }
    }
}
