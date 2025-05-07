/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.util;


import org.cloudfoundry.identity.uaa.impl.config.NestedMapPropertySource;
import org.springframework.core.env.CompositePropertySource;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.PropertySource;
import org.yaml.snakeyaml.Yaml;

import java.util.AbstractMap;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import static java.util.Map.Entry.comparingByKey;

public class UaaMapUtils {

    public static Map<String, Object> flatten(Map<String, Object> map) {
        HashMap<String, Object> result = new HashMap<>();
        if (map == null || map.isEmpty()) {
            return result;
        }
        NestedMapPropertySource properties = new NestedMapPropertySource("map", map);
        for (String property : properties.getPropertyNames()) {
            if (properties.getProperty(property) != null) {
                result.put(property, properties.getProperty(property));
            }
        }
        return result;
    }


    public static Map<String, Object> getPropertiesStartingWith(ConfigurableEnvironment aEnv,
                                                                String aKeyPrefix) {
        Map<String, Object> result = new HashMap<>();
        Map<String, Object> map = getAllProperties(aEnv);
        for (Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            if (key.startsWith(aKeyPrefix)) {
                result.put(key, entry.getValue());
            }
        }
        return result;
    }

    public static Map<String, Object> getAllProperties(ConfigurableEnvironment aEnv) {
        Map<String, Object> result = new HashMap<>();
        aEnv.getPropertySources().forEach(ps -> addAll(result, getAllProperties(ps)));
        return result;
    }

    public static Map<String, Object> getAllProperties(PropertySource<?> aPropSource) {
        Map<String, Object> result = new HashMap<>();

        if (aPropSource instanceof CompositePropertySource cps) {
            cps.getPropertySources().forEach(ps -> addAll(result, getAllProperties(ps)));
            return result;
        }

        if (aPropSource instanceof EnumerablePropertySource<?> ps) {
            Arrays.asList(ps.getPropertyNames()).forEach(key -> result.put(key, ps.getProperty(key)));
            return result;
        }

        //unable to iterate over it

        return result;
    }

    private static void addAll(Map<String, Object> aBase, Map<String, Object> aToBeAdded) {
        for (Entry<String, Object> entry : aToBeAdded.entrySet()) {
            if (aBase.containsKey(entry.getKey())) {
                continue;
            }
            aBase.put(entry.getKey(), entry.getValue());
        }
    }

    @SafeVarargs
    public static <K, V, E extends Map.Entry<K, V>> Map<K, V> map(E... entries) {
        Map<K, V> map = new HashMap<>();
        for (E entry : entries) {
            map.put(entry.getKey(), entry.getValue());
        }
        return map;
    }

    public static <K, V> Map.Entry<K, V> entry(K key, V value) {
        return new AbstractMap.SimpleEntry<>(key, value);
    }

    public static <K extends Comparable<? super K>, V> Map<K, V> sortByKeys(Map<K, V> map) {
        List<Entry<K, V>> sortedEntries = map
                .entrySet()
                .stream()
                .sorted(comparingByKey())
                .toList();
        LinkedHashMap<K, V> result = new LinkedHashMap<>();
        for (Map.Entry<K, V> entry : sortedEntries) {
            Object value = entry.getValue();
            if (value instanceof Map map1) {
                value = sortByKeys(map1);
            }
            result.put(entry.getKey(), (V) value);
        }
        return result;
    }

    public static <K extends Comparable<? super K>, V> String prettyPrintYaml(Map<K, V> map) {
        Yaml yaml = new Yaml(UaaYamlUtils.getDefaultDumperOptions());
        return yaml.dump(sortByKeys(map));
    }

    /**
     * Hide the values in a config map (e.g. for logging).
     *
     * @param map a map with String keys (e.g. Properties) and String or nested
     *            map values
     * @return new properties with no plaintext passwords and secrets
     */
    public static Map<String, ?> redactValues(Map<String, ?> map) {
        Map<String, Object> result = new LinkedHashMap<>(map);
        for (String key : map.keySet()) {
            Object value = map.get(key);
            if (value == null) {
                result.put(key, value);
            } else if (value instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, ?> bare = (Map<String, ?>) value;
                result.put(key, redactValues(bare));
            } else if (value instanceof String strValue && UaaStringUtils.isEmpty(strValue)) {
                result.put(key, "");
            } else {
                result.put(key, "<redacted>");
            }
        }
        return result;
    }
}
