/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.statsd;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.management.*;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularDataSupport;
import java.util.*;

@SuppressWarnings("restriction")
public class MBeanMap extends AbstractMap<String, Object> {

    private static Logger logger = LoggerFactory.getLogger(MBeanMap.class);

    private Map<String, Object> map = new HashMap<>();

    private final MBeanInfo info;

    private final MBeanServerConnection server;

    private final ObjectName name;

    public MBeanMap() {
        this(null, null);
    }

    public MBeanMap(MBeanServerConnection server, ObjectName name) {
        this.server = server;
        this.name = name;
        if (server != null) {
            try {
                info = server.getMBeanInfo(name);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        } else {
            info = null;
        }
    }

    @Override
    public Object put(String key, Object value) {
        return map.put(key, value);
    }

    @Override
    public Set<java.util.Map.Entry<String, Object>> entrySet() {
        boolean initialized = false;
        if (!initialized && info != null) {
            MBeanAttributeInfo[] attributes = info.getAttributes();
            for (MBeanAttributeInfo attribute : attributes) {
                String key = attribute.getName();
                try {
                    Object value = server.getAttribute(name, key);
                    verySafePut(map, key, value);
                } catch (Exception e) {
                    logger.trace("Cannot extract attribute: {}", key);
                }
            }
            MBeanOperationInfo[] operations = info.getOperations();
            for (MBeanOperationInfo operation : operations) {
                String key = operation.getName();
                if (key.startsWith("get") && operation.getSignature().length == 0) {
                    String attribute = StringUtils.camelToUnderscore(key.substring(3));
                    if (map.containsKey(attribute)) {
                        continue;
                    }
                    try {
                        Object value = server.invoke(name, key, null, null);
                        verySafePut(map, attribute, value);
                    } catch (Exception e) {
                        logger.trace("Cannot extract operation: {}", key);
                    }
                }
            }
        }
        return map.entrySet();
    }

    private Object getCompositeWrapper(Object value) {
        return getCompositeWrapper(value, true);
    }

    private Object getCompositeWrapper(Object value, boolean prettifyKeys) {
        if (value instanceof CompositeData composite) {
            Map<Object, Object> map = new HashMap<>();
            for (String key : composite.getCompositeType().keySet()) {
                safePut(map, key, composite.get(key));
            }
            return map;
        }
        if (value instanceof TabularDataSupport composite) {
            Map<Object, Object> map = new HashMap<>();
            for (Entry<Object, Object> entry : composite.entrySet()) {
                Object wrapper = getCompositeWrapper(entry.getValue());
                if (isKeyValuePair(wrapper)) {
                    String key = getKey(wrapper);
                    safePut(map, key, getValue(wrapper), prettifyKeys);
                } else {
                    safePut(map, getCompositeWrapper(entry.getKey()), wrapper, prettifyKeys);
                }
            }
            return map;
        }
        if (value instanceof Collection<?> composite) {
            List<Object> list = new ArrayList<>();
            for (Object element : composite) {
                list.add(getCompositeWrapper(element));
            }
            return list;
        }
        if (value.getClass().isArray()) {
            List<Object> list = new ArrayList<>();
            for (Object element : (Object[]) value) {
                list.add(getCompositeWrapper(element));
            }
            return list;
        }
        return value;
    }

    private void safePut(Map<Object, Object> map, Object key, Object value) {
        safePut(map, key, value, true);
    }

    private void verySafePut(Map<?, Object> map, Object key, Object value) {
        @SuppressWarnings("unchecked")
        Map<Object, Object> target = (Map<Object, Object>) map;
        safePut(target, key, value);
    }

    private void safePut(Map<Object, Object> map, Object key, Object value, boolean prettifyKeys) {
        Object property = key;
        if (key instanceof String string && prettifyKeys) {
            property = StringUtils.camelToUnderscore(string);
        }
        // Don't prettify system property keys in case user has added upper case properties
        map.put(property, getCompositeWrapper(value, prettifyKeys && !key.equals("SystemProperties")));
    }

    private Object getValue(Object wrapper) {
        @SuppressWarnings("unchecked")
        Map<Object, Object> map = (Map<Object, Object>) wrapper;
        return map.get("value");
    }

    private String getKey(Object wrapper) {
        @SuppressWarnings("unchecked")
        Map<String, String> map = (Map<String, String>) wrapper;
        return map.get("key");
    }

    private boolean isKeyValuePair(Object wrapper) {
        if (!(wrapper instanceof Map)) {
            return false;
        }
        @SuppressWarnings("unchecked")
        Map<Object, Object> map = (Map<Object, Object>) wrapper;
        if (map.size() > 2) {
            return false;
        }
        return map.containsKey("key") && map.containsKey("value");
    }

}