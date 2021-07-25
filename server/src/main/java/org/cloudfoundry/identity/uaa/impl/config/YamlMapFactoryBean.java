/*******************************************************************************
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

import org.springframework.beans.factory.FactoryBean;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Factory for Map that reads from a YAML source. YAML is a nice human-readable
 * format for configuration, and it has
 * some useful hierarchical properties. It's more or less a superset of JSON, so
 * it has a lot of similar features. If
 * multiple resources are provided the later ones will override entries in the
 * earlier ones hierarchically - that is all
 * entries with the same nested key of type Map at any depth are merged. For
 * example:
 * 
 * <pre>
 * foo:
 *   bar:
 *    one: two
 * three: four
 * 
 * </pre>
 * 
 * plus (later in the list)
 * 
 * <pre>
 * foo:
 *   bar:
 *    one: 2
 * five: six
 * 
 * </pre>
 * 
 * results in an effecive input of
 * 
 * <pre>
 * foo:
 *   bar:
 *    one: 2
 *    three: four
 * five: six
 * 
 * </pre>
 * 
 * Note that the value of "foo" in the first document is not simply replaced with the value in the second, but it's nested values are merged.
 * 
 * @author Dave Syer
 * 
 */
public class YamlMapFactoryBean extends YamlProcessor implements FactoryBean<Map<String, Object>> {

    private Map<String, Object> instance;

    @Override
    public Map<String, Object> getObject() {
        if (instance == null) {
            instance = doGetObject();
        }
        return instance;
    }

    private Map<String, Object> doGetObject() {
        final Map<String, Object> result = new LinkedHashMap<String, Object>();
        MatchCallback callback = (properties, map) -> merge(result, map);
        process(callback);
        return result;
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private void merge(Map<String, Object> output, Map<String, Object> map) {
        for (Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            Object existing = output.get(key);
            if (value instanceof Map && existing instanceof Map) {
                Map<String, Object> result = new LinkedHashMap<String, Object>((Map) existing);
                merge(result, (Map) value);
                output.put(key, result);
            }
            else {
                output.put(key, value);
            }
        }
    }

    @Override
    public Class<?> getObjectType() {
        return Map.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }

}
