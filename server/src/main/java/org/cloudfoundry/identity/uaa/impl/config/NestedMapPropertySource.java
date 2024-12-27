/*
 * *****************************************************************************
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
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.impl.config;

import org.springframework.core.env.MapPropertySource;
import org.springframework.util.ObjectUtils;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * A property source based on a map that might contain nested maps and
 * collections. Property keys can be nested using
 * period separators.
 *
 * @author Dave Syer
 *
 */
public class NestedMapPropertySource extends MapPropertySource {

    private final Map<String, Object> cache = new HashMap<>();

    private boolean initialized;

    /**
     * @param name the name of this property source
     * @param source the source map
     */
    @SuppressWarnings("unchecked")
    public NestedMapPropertySource(String name, Map<String, ?> source) {
        super(name, (Map<String, Object>) source);
    }

    @Override
    public Object getProperty(String name) {
        Object value = this.source.get(name);
        if (value != null) {
            return value;
        }
        populateCache();
        value = this.cache.get(name);
        return value;
    }

    @Override
    public boolean containsProperty(String name) {
        return null != getProperty(name);
    }

    @Override
    public String[] getPropertyNames() {
        populateCache();
        return this.cache.keySet().toArray(new String[0]);
    }

    private void populateCache() {
        if (initialized) {
            return;
        }
        appendCache(this.cache, new HashSet<>(), this.source, null);
        initialized = true;
    }

    private void appendCache(Map<String, Object> output, Set<String> seen, Map<String, Object> input, String path) {

        synchronized (this.cache) {

            seen.add(ObjectUtils.getIdentityHexString(input));

            for (Entry<String, Object> entry : input.entrySet()) {
                String key = entry.getKey();
                if (StringUtils.hasText(path)) {
                    if (key.startsWith("[")) {
                        key = path + key;
                    } else {
                        key = path + "." + key;
                    }
                }
                Object value = entry.getValue();
                if (value instanceof String) {
                    output.put(key, value);
                } else if (value instanceof Map) {
                    // Need a compound key
                    @SuppressWarnings("unchecked")
                    Map<String, Object> map = (Map<String, Object>) value;
                    output.put(key, map);
                    if (!seen.contains(ObjectUtils.getIdentityHexString(map))) {
                        appendCache(output, seen, map, key);
                    }
                } else if (value instanceof Collection) {
                    // Need a compound key
                    @SuppressWarnings("unchecked")
                    Collection<Object> collection = (Collection<Object>) value;
                    output.put(key, collection);
                    int count = 0;
                    for (Object object : collection) {
                        String index = "[" + (count++) + "]";
                        if (!seen.contains(ObjectUtils.getIdentityHexString(object))) {
                            appendCache(output, seen, Collections.singletonMap(index, object), key);
                        } else {
                            output.put(key + index, object);
                        }
                    }
                } else {
                    output.put(key, value);
                }
            }

        }

    }

}
