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
package org.cloudfoundry.identity.uaa.config;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.springframework.beans.factory.FactoryBean;

/**
 * Factory for Map that reads from a YAML source. YAML is a nice human-readable format for configuration, and it has
 * some useful hierarchical properties. It's more or less a superset of JSON, so it has a lot of similar features.
 * 
 * @author Dave Syer
 * 
 */
public class YamlMapFactoryBean extends YamlProcessor implements FactoryBean<Map<String, Object>> {

	@Override
	public Map<String, Object> getObject() {
		final Map<String, Object> result = new LinkedHashMap<String, Object>();
		MatchCallback callback = new MatchCallback() {
			@Override
			public void process(Properties properties, Map<String, Object> map) {
				result.putAll(map);
			}
		};
		process(callback);
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