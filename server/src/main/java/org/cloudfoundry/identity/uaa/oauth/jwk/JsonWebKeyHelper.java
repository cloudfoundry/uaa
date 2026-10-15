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

import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;
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
    /** Far above real key sets (100 keys with certificate chains stay below 2,000), far below a 1 MiB worst case. */
    public static final int MAX_JWKS_JSON_VALUES = 10_000;
    private static final Pattern PEM_DATA = Pattern.compile("-----BEGIN (.*)-----(.*)-----END (.*)-----", Pattern.DOTALL);
    private static final Pattern WS_DATA = Pattern.compile("\\s", Pattern.UNICODE_CHARACTER_CLASS);
    private static final Pattern JSON_DATA = Pattern.compile("^\\{(.*)\\:(.*)\\}$", Pattern.DOTALL);
    private static final int PEM_TYPE = 1;
    private static final int PEM_CONTENT = 2;

    private JsonWebKeyHelper() {
    }

    public static JsonWebKeySet<JsonWebKey> deserialize(String s) {
        if (!hasTopLevelKeysMember(s)) {
            return new JsonWebKeySet<>(Collections.singletonList(JsonUtils.readValue(s, JsonWebKey.class)));
        } else {
            return JsonUtils.readValue(s, new TypeReference<JsonWebKeySet<JsonWebKey>>() {
            });
        }
    }

    /**
     * Compares top-level property names after JSON unescaping, as {@link #countKeys(String)} and the object mapping
     * do, so a {@code "keys"} value or nested member does not make a single JWK a set. Content that is not valid JSON
     * falls back to a substring check, leaving the mapping to report the error.
     */
    private static boolean hasTopLevelKeysMember(String s) {
        try (JsonParser parser = JsonMapper.shared().createParser(s)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return false;
            }
            while (parser.nextToken() == JsonToken.PROPERTY_NAME) {
                if ("keys".equals(parser.currentName())) {
                    return true;
                }
                parser.nextToken();
                parser.skipChildren();
            }
            return false;
        } catch (JacksonException e) {
            return s.contains("\"keys\"");
        }
    }

    /**
     * Counts the keys of a JWK set document (1 for a single JWK without a top-level {@code keys} member) with a
     * streaming pass that does not build them, so callers can reject oversized documents before the far more
     * memory-intensive object mapping. Property names are compared after JSON unescaping, as the mapping does.
     *
     * @throws JsonUtils.JsonUtilException if the content is not valid JSON, has more than one top-level {@code keys}
     *                                     member (the object mapping would keep the last one), or contains more than
     *                                     {@link #MAX_JWKS_JSON_VALUES} JSON values in total
     */
    public static int countKeys(String s) {
        try (JsonParser parser = JsonMapper.shared().createParser(s)) {
            if (parser.nextToken() != JsonToken.START_OBJECT) {
                return 1;
            }
            int keys = 0;
            int values = 1;
            boolean keysSeen = false;
            while (next(parser) == JsonToken.PROPERTY_NAME) {
                String name = parser.currentName();
                JsonToken value = next(parser);
                if ("keys".equals(name)) {
                    if (keysSeen) {
                        throw invalidJwkSet("Duplicate \"keys\" member in JWK set");
                    }
                    keysSeen = true;
                    if (value == JsonToken.START_ARRAY) {
                        values++;
                        while (next(parser) != JsonToken.END_ARRAY) {
                            keys++;
                            values = requireValueLimit(values + countValues(parser));
                        }
                        continue;
                    }
                }
                values = requireValueLimit(values + countValues(parser));
            }
            return keysSeen ? keys : 1;
        } catch (JacksonException e) {
            throw new JsonUtils.JsonUtilException(e);
        }
    }

    private static int requireValueLimit(int values) {
        if (values > MAX_JWKS_JSON_VALUES) {
            throw invalidJwkSet("JWK set document exceeds " + MAX_JWKS_JSON_VALUES + " JSON values");
        }
        return values;
    }

    /** Counts the value at the parser's current token, including all values nested in it, and moves past it. */
    private static int countValues(JsonParser parser) {
        if (!parser.currentToken().isStructStart()) {
            return 1;
        }
        int values = 1;
        int depth = 1;
        while (depth > 0) {
            JsonToken token = next(parser);
            if (token.isStructStart()) {
                depth++;
                values++;
            } else if (token.isStructEnd()) {
                depth--;
            } else if (token != JsonToken.PROPERTY_NAME) {
                values++;
            }
            requireValueLimit(values);
        }
        return values;
    }

    /** Like {@link JsonParser#nextToken()}, which returns null at the end of input instead of failing on truncation. */
    private static JsonToken next(JsonParser parser) {
        JsonToken token = parser.nextToken();
        if (token == null) {
            throw invalidJwkSet("Unexpected end of JWK set document");
        }
        return token;
    }

    private static JsonUtils.JsonUtilException invalidJwkSet(String message) {
        return new JsonUtils.JsonUtilException(new IllegalArgumentException(message));
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
