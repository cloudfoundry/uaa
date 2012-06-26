/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.util;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * @author Dave Syer
 * 
 */
public class UaaStringUtils {

	/**
	 * Convert a string from camel case to underscores, also replacing periods with underscores (so for example a fully
	 * qualified Java class name gets underscores everywhere).
	 * 
	 * @param value a camel case String
	 * @return the same value with camels comverted to underscores
	 */
	public static String camelToUnderscore(String value) {
		String result = value.replace(" ", "_");
		result = result.replaceAll("([a-z])([A-Z])", "$1_$2");
		result = result.replace(".", "_");
		result = result.toLowerCase();
		return result;
	}

	public static String getErrorName(Exception e) {
		String name = e.getClass().getSimpleName();
		name = UaaStringUtils.camelToUnderscore(name);
		if (name.endsWith("_exception")) {
			name = name.substring(0, name.lastIndexOf("_exception"));
		}
		return name;
	}

	/**
	 * Hide the passwords and secrets in a config map (e.g. for logging).
	 * 
	 * @param map a map with String keys (e.g. Properties) and String or nested map values
	 * @return new properties with no plaintext passwords and secrets
	 */
	public static Map<String, ?> hidePasswords(Map<String, ?> map) {
		Map<String, Object> result = new LinkedHashMap<String, Object>();
		result.putAll(map);
		for (String key : map.keySet()) {
			Object value = map.get(key);
			if (value instanceof String) {
				if (isPassword(key)) {
					result.put(key, "#");
				}
			} else if (value instanceof Map) {
				@SuppressWarnings("unchecked")
				Map<String, ?> bare = (Map<String, ?>) value;
				result.put(key, hidePasswords(bare));
			}
		}
		return result;
	}

	/**
	 * @param properties
	 * @return new properties with no plaintext passwords
	 */
	public static Properties hidePasswords(Properties properties) {
		Properties result = new Properties();
		result.putAll(properties);
		for (String key : properties.stringPropertyNames()) {
			if (isPassword(key)) {
				result.put(key, "#");
			}
		}
		return result;
	}

	/**
	 * Extract a Map from some properties by removing a prefix from the key names.
	 * 
	 * @param properties the properties to use
	 * @param prefix the prefix to strip from key names
	 * @return a map of String values
	 */
	public static Map<String, ?> getMapFromProperties(Properties properties, String prefix) {
		Map<String, Object> result = new HashMap<String, Object>();
		for (String key : properties.stringPropertyNames()) {
			if (key.startsWith(prefix)) {
				String name = key.substring(prefix.length());
				result.put(name, properties.getProperty(key));
			}
		}
		return result;
	}

	private static boolean isPassword(String key) {
		return key.endsWith("password") || key.endsWith("secret") || key.endsWith("signing-key");
	}

}
