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
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;
import org.yaml.snakeyaml.Yaml;

/**
 * Factory for Map that reads from a YAML source. YAML is a nice human-readable format for configuration, and it has
 * some useful hierarchical properties. It's more or less a superset of JSON, so it has a lot of similar features.
 * 
 * @author Dave Syer
 * 
 */
public class YamlMapFactoryBean implements FactoryBean<Map<String, Object>> {

	private static final Log logger = LogFactory.getLog(YamlMapFactoryBean.class);

	private Resource[] resources = new Resource[0];

	private boolean ignoreResourceNotFound = false;

	/**
	 * @param ignoreResourceNotFound the flag value to set
	 */
	public void setIgnoreResourceNotFound(boolean ignoreResourceNotFound) {
		this.ignoreResourceNotFound = ignoreResourceNotFound;
	}

	/**
	 * @param resource the resource to set
	 */
	public void setResources(Resource[] resources) {
		this.resources = resources;
	}

	@Override
	public Map<String, Object> getObject() throws Exception {
		Yaml yaml = new Yaml();
		Map<String, Object> result = new LinkedHashMap<String, Object>();
		for (Resource resource : resources) {
			try {
				@SuppressWarnings("unchecked")
				Map<String, Object> map = (Map<String, Object>) yaml.load(resource.getInputStream());
				result.putAll(map);
			}
			catch (IOException e) {
				if (ignoreResourceNotFound) {
					if (logger.isWarnEnabled()) {
						logger.warn("Could not load properties from " + resource + ": " + e.getMessage());
					}
				}
				else {
					throw e;
				}
			}
		}
		return result;
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