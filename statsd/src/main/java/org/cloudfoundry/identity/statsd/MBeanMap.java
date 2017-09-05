/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.statsd;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanAttributeInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeDataSupport;
import javax.management.openmbean.TabularDataSupport;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.management.LazyCompositeData;

@SuppressWarnings("restriction")
public class MBeanMap extends AbstractMap<String, Object>{

	private static Log logger = LogFactory.getLog(MBeanMap.class);

	private Map<String, Object> map = new HashMap<String, Object>();

	private boolean initialized = false;

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
		if (!initialized && info != null) {
			MBeanAttributeInfo[] attributes = info.getAttributes();
			for (MBeanAttributeInfo attribute : attributes) {
				String key = attribute.getName();
				try {
					Object value = server.getAttribute(name, key);
					verySafePut(map, key, value);
				} catch (Exception e) {
					logger.trace("Cannot extract attribute: " + key);
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
						logger.trace("Cannot extract operation: " + key);
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
		if (value instanceof CompositeDataSupport) {
			Map<Object, Object> map = new HashMap<Object, Object>();
			CompositeDataSupport composite = (CompositeDataSupport) value;
			for (String key : composite.getCompositeType().keySet()) {
				safePut(map, key, composite.get(key));
			}
			return map;
		}
		if (value instanceof LazyCompositeData) {
			Map<Object, Object> map = new HashMap<Object, Object>();
			LazyCompositeData composite = (LazyCompositeData) value;
			for (String key : composite.getCompositeType().keySet()) {
				safePut(map, key, composite.get(key));
			}
			return map;
		}
		if (value instanceof TabularDataSupport) {
			Map<Object, Object> map = new HashMap<Object, Object>();
			TabularDataSupport composite = (TabularDataSupport) value;
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
		if (value instanceof Collection) {
			Collection<?> composite = (Collection<?>) value;
			List<Object> list = new ArrayList<Object>();
			for (Object element : composite) {
				list.add(getCompositeWrapper(element));
			}
			return list;
		}
		if (value.getClass().isArray()) {
			List<Object> list = new ArrayList<Object>();
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

	private void verySafePut(Map<? extends Object, Object> map, Object key, Object value) {
		@SuppressWarnings("unchecked")
		Map<Object, Object> target = (Map<Object, Object>) map;
		safePut(target, key, value);
	}

	private void safePut(Map<Object, Object> map, Object key, Object value, boolean prettifyKeys) {
		Object property = key;
		if (key instanceof String && prettifyKeys) {
			property = StringUtils.camelToUnderscore((String) key);
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
		if (map.containsKey("key") && map.containsKey("value")) {
			return true;
		}
		return false;
	}

}