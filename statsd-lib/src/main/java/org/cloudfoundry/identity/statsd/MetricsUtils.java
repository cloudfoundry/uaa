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

import org.cloudfoundry.identity.uaa.metrics.UaaMetrics;

import javax.management.JMX;
import javax.management.MBeanServerConnection;
import javax.management.NotificationEmitter;
import javax.management.ObjectName;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;


public class MetricsUtils {

    public UaaMetrics getUaaMetrics(MBeanServerConnection server) throws Exception {
        ObjectName mbeanName = new ObjectName("cloudfoundry.identity:name=ServerRequests");
        return JMX.newMBeanProxy(server, mbeanName, UaaMetrics.class, false);
    }

    public NotificationEmitter getUaaMetricsSubscriber(MBeanServerConnection server) throws Exception {
        ObjectName mbeanName = new ObjectName("cloudfoundry.identity:name=ServerRequests");
        return (NotificationEmitter) JMX.newMBeanProxy(server, mbeanName, UaaMetrics.class, true);
    }

    public Map<String, ?> pullUpMap(String domain, String pattern, MBeanServerConnection server) throws Exception {
        @SuppressWarnings("unchecked")
        Map<String, ?> map = (Map<String, ?>) getMBeans(domain, pattern, server).get(domain);
        return map == null ? Collections.emptyMap() : map;
    }

    public Map<String, ?> getMBeans(String domain, String pattern, MBeanServerConnection server) throws Exception {
        Set<ObjectName> names = server.queryNames(ObjectName.getInstance(domain + ":" + pattern), null);

        Map<String, Object> result = new LinkedHashMap<>();

        for (ObjectName name : names) {

            Map<String, Object> map = new MBeanMap(server, name);

            Map<String, Object> objects = getMap(result, domain);

            String type = name.getKeyProperty("type");
            if (type != null) {
                objects = getMap(objects, type);
            }

            String key = name.getKeyProperty("name");
            if (key != null) {
                objects = getMap(objects, key);
            }

            for (String property : name.getKeyPropertyList().keySet()) {
                if ("type".equals(property) || "name".equals(property)) {
                    continue;
                }
                key = StringUtils.camelToUnderscore(property);
                objects = getMap(objects, key);
                String value = name.getKeyProperty(property);
                objects = getMap(objects, value);
            }

            if (key == null) {
                key = type;
            }
            if (key == null) {
                key = domain;
            }
            objects.putAll(map);
        }

        return result;
    }

    private Map<String, Object> getMap(Map<String, Object> result, String key) {
        if (!result.containsKey(key)) {
            result.put(key, new MBeanMap());
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> objects = (Map<String, Object>) result.get(key);
        return objects;
    }


}
