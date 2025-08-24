/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serial;
import java.util.Date;
import java.util.Map;

public class JsonUtils {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private JsonUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static String writeValueAsString(Object object) throws JsonUtilException {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static byte[] writeValueAsBytes(Object object) throws JsonUtilException {
        try {
            return objectMapper.writeValueAsBytes(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(String s, Class<T> clazz) throws JsonUtilException {
        try {
            if (hasText(s)) {
                return objectMapper.readValue(s, clazz);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static Map<String, Object> readValueAsMap(final String input) {
        try {
            final JsonNode rootNode = objectMapper.readTree(input);
            return getNodeAsMap(rootNode);
        } catch (final JsonProcessingException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(byte[] data, Class<T> clazz) throws JsonUtilException {
        try {
            if (data != null && data.length > 0) {
                return objectMapper.readValue(data, clazz);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(String s, TypeReference<T> typeReference) {
        try {
            if (hasText(s)) {
                return objectMapper.readValue(s, typeReference);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(byte[] data, TypeReference<T> typeReference) {
        try {
            if (data != null && data.length > 0) {
                return objectMapper.readValue(data, typeReference);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T convertValue(Object object, Class<T> toClazz) throws JsonUtilException {
        try {
            if (object == null) {
                return null;
            } else {
                return objectMapper.convertValue(object, toClazz);
            }
        } catch (IllegalArgumentException e) {
            throw new JsonUtilException(e);
        }
    }

    public static JsonNode readTree(JsonParser p) {
        try {
            return objectMapper.readTree(p);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static JsonNode readTree(String s) {
        try {
            if (hasText(s)) {
                return objectMapper.readTree(s);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static class JsonUtilException extends RuntimeException {
        @Serial
        private static final long serialVersionUID = -4804245225960963421L;

        public JsonUtilException(Throwable cause) {
            super(cause);
        }
    }

    public static String serializeExcludingProperties(Object object, String... propertiesToExclude) {
        String serialized = JsonUtils.writeValueAsString(object);
        Map<String, Object> properties = JsonUtils.readValue(serialized, new TypeReference<>() {
        });
        for (String property : propertiesToExclude) {
            if (property.contains(".")) {
                String[] split = property.split("\\.", 2);
                if (properties != null && properties.containsKey(split[0])) {
                    Object inner = properties.get(split[0]);
                    properties.put(split[0], JsonUtils.readValue(serializeExcludingProperties(inner, split[1]), new TypeReference<Map<String, Object>>() {
                    }));
                }
            } else {
                if (properties != null) {
                    properties.remove(property);
                }
            }
        }
        return JsonUtils.writeValueAsString(properties);
    }

    public static String getNodeAsString(JsonNode node, String fieldName, String defaultValue) {
        JsonNode typeNode = node.get(fieldName);
        return typeNode == null ? defaultValue : typeNode.asText(defaultValue);
    }

    public static int getNodeAsInt(JsonNode node, String fieldName, int defaultValue) {
        JsonNode typeNode = node.get(fieldName);
        return typeNode == null ? defaultValue : typeNode.asInt(defaultValue);
    }

    public static boolean getNodeAsBoolean(JsonNode node, String fieldName, boolean defaultValue) {
        JsonNode typeNode = node.get(fieldName);
        return typeNode == null ? defaultValue : typeNode.asBoolean(defaultValue);
    }

    public static Date getNodeAsDate(JsonNode node, String fieldName) {
        JsonNode typeNode = node.get(fieldName);
        long date = typeNode == null ? -1 : typeNode.asLong(-1);
        if (date == -1) {
            return null;
        } else {
            return new Date(date);
        }
    }

    public static Map<String, Object> getNodeAsMap(JsonNode node) {
        return objectMapper.convertValue(node, Map.class);
    }

    public static boolean hasLength(CharSequence str) {
        return !(str == null || str.isEmpty());
    }

    public static boolean hasText(CharSequence str) {
        if (!hasLength(str)) {
            return false;
        }

        int strLen = str.length();
        for (int i = 0; i < strLen; i++) {
            if (!Character.isWhitespace(str.charAt(i))) {
                return true;
            }
        }
        return false;
    }
}
