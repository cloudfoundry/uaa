/**
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
package org.cloudfoundry.identity.uaa.config;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.Yaml;

/**
 * Factory for Java Properties that reads from a YAML source. YAML is a nice human-readable format for configuration,
 * and it has some useful hierarchical properties. It's more or less a superset of JSON, so it has a lot of similar
 * features. The Properties created by this factory have nested paths for hierarchical objects, so for instance this
 * YAML
 * 
 * <pre>
 * environments:
 *   dev:
 *     url: http://dev.bar.com
 *     name: Developer Setup
 *   prod:
 *     url: http://foo.bar.com
 *     name: My Cool App
 * </pre>
 * 
 * is transformed into these Properties:
 * 
 * <pre>
 * environments.dev.url=http://dev.bar.com
 * environments.dev.name=Developer Setup
 * environments.prod.url=http://foo.bar.com
 * environments.prod.name=My Cool App
 * </pre>
 * 
 * Lists are represented as comma-separated values (useful for simple String values) and also as property keys with
 * <code>[]</code> dereferencers, for example this YAML:
 * 
 * <pre>
 * servers:
 * - dev.bar.com
 * - foo.bar.com
 * </pre>
 * 
 * becomes java Properties like this:
 * 
 * <pre>
 * servers=dev.bar.com,foo.bar.com
 * servers[0]=dev.bar.com
 * servers[1]=foo.bar.com
 * </pre>
 * 
 * @author Dave Syer
 * 
 */
public class YamlPropertiesFactoryBean implements FactoryBean<Properties> {

	private static final Log logger = LogFactory.getLog(YamlPropertiesFactoryBean.class);

	private Resource resource = new ByteArrayResource(new byte[0]);

	private boolean ignoreResourceNotFound = false;

	private Map<String, String> keyReplacements = new HashMap<String, String>();

	/**
	 * A map of key replacements. Values in the target whose keys start with a key in this map will be re-added to the
	 * output properties with the alternative key stem given by the value in this map. E.g.
	 * 
	 * <pre>
	 * environments.dev.url=http://dev.bar.com
	 * environments.dev.name=Developer Setup
	 * environments.prod.url=http://foo.bar.com
	 * environments.prod.name=My Cool App
	 * </pre>
	 * 
	 * when mapped with <code>keyReplacements = {"environments.prod": "environment"}</code> would end up as
	 * 
	 * <pre>
	 * environment.url=http://foo.bar.com
	 * environment.name=My Cool App
	 * environments.dev.url=http://dev.bar.com
	 * environments.dev.name=Developer Setup
	 * environments.prod.url=http://foo.bar.com
	 * environments.prod.name=My Cool App
	 * </pre>
	 * 
	 * @param keyReplacements the keyReplacements to set
	 */
	public void setKeyReplacements(Map<String, String> keyReplacements) {
		this.keyReplacements = keyReplacements;
	}

	/**
	 * @param ignoreResourceNotFound the flag value to set
	 */
	public void setIgnoreResourceNotFound(boolean ignoreResourceNotFound) {
		this.ignoreResourceNotFound = ignoreResourceNotFound;
	}

	/**
	 * @param resource the resource to set
	 */
	public void setResource(Resource resource) {
		this.resource = resource;
	}

	@Override
	public Properties getObject() {
		Yaml yaml = new Yaml();
		Properties properties = new Properties();
		try {
			if (logger.isDebugEnabled()) {
				logger.debug("Loading properties from " + resource);
			}
			@SuppressWarnings("unchecked")
			Map<String, Object> map = (Map<String, Object>) yaml.load(resource.getInputStream());
			assignProperties(properties, map, null);
		}
		catch (IOException e) {
			if (ignoreResourceNotFound) {
				if (logger.isWarnEnabled()) {
					logger.warn("Could not load properties from " + resource + ": " + e.getMessage());
				}
			}
			else {
				throw new IllegalStateException(e);
			}
		}
		return properties;
	}

	@Override
	public Class<?> getObjectType() {
		return Properties.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}

	private void assignProperties(Properties properties, Map<String, Object> input, String path) {
		for (Entry<String, Object> entry : input.entrySet()) {
			String key = entry.getKey();
			if (StringUtils.hasText(path)) {
				if (key.startsWith("[")) {
					key = path + key;
				}
				else {
					key = path + "." + key;
				}
			}
			Object value = entry.getValue();
			if (value instanceof String) {
				addWithReplacement(properties, key, value);
			}
			else if (value instanceof Map) {
				// Need a compound key
				@SuppressWarnings("unchecked")
				Map<String, Object> map = (Map<String, Object>) value;
				assignProperties(properties, map, key);
			}
			else if (value instanceof Collection) {
				// Need a compound key
				@SuppressWarnings("unchecked")
				Collection<Object> collection = (Collection<Object>) value;
				addWithReplacement(properties, key, StringUtils.collectionToCommaDelimitedString(collection));
				int count = 0;
				for (Object object : collection) {
					assignProperties(properties, Collections.singletonMap("[" + (count++) + "]", object), key);
				}
			}
			else {
				addWithReplacement(properties, key, value == null ? "" : value);
			}
		}
	}

	protected void addWithReplacement(Properties props, String key, Object value) {
		String name = key;
		for (String stem : keyReplacements.keySet()) {
			if (name.startsWith(stem)) {
				name = name.replace(stem, keyReplacements.get(stem));
				if (name.startsWith(".")) {
					name = name.substring(1);
				}
			}
		}
		props.put(name, value);
	}

}