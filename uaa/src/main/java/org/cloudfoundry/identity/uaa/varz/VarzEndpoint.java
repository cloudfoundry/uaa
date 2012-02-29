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
package org.cloudfoundry.identity.uaa.varz;

import java.io.IOException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class VarzEndpoint implements EnvironmentAware {

	private static Log logger = LogFactory.getLog(VarzEndpoint.class);

	private MBeanServerConnection server;
	
	private Map<String,Object> statix = new LinkedHashMap<String, Object>();

	private Environment environment;
	
	@Override
	public void setEnvironment(Environment environment) {
		this.environment = environment;	
	}
	
	public void setStaticValues(Map<String, Object> statics) {
		this.statix = new LinkedHashMap<String, Object>(statics);
	}

	public void setServer(MBeanServerConnection server) {
		this.server = server;
	}

	@RequestMapping("/varz")
	@ResponseBody
	public Map<String, ?> getVarz() throws Exception {
		Map<String, Object> result = new LinkedHashMap<String, Object>(statix);
		result.putAll(getMBeans("java.lang:*"));
		result.put("env", getHostProperties());
		result.putAll(getMBeans("Catalina:type=GlobalRequestProcessor,*"));
		Map<String, ?> tomcat = getMBeans("*:type=GlobalRequestProcessor,*");
		if (!tomcat.isEmpty()) {
			if (tomcat.size() == 1) {
				// tomcat 6.0.23, 6.0.35 have different default domains so normalize...
				result.put("tomcat", tomcat.values().iterator().next());
			} else {
				result.putAll(tomcat);
			}
		}
		result.putAll(getMBeans("spring.application:*"));
		if (environment!=null) {
			result.put("spring.profiles.active", environment.getActiveProfiles());
		}
		return result;
	}

	@RequestMapping("/varz/mbeans")
	@ResponseBody
	public Map<String, ?> getMBeans(@RequestParam(required = false, defaultValue = "java.lang:*") String pattern)
			throws Exception {

		Map<String, Object> result = new LinkedHashMap<String, Object>();
		Set<ObjectName> names = server.queryNames(ObjectName.getInstance(pattern), null);

		for (ObjectName name : names) {

			String domain = name.getDomain();
			Map<String, Object> map = new MBeanMap(server, name);

			Map<String, Object> objects = getMap((Map<String, Object>) result, domain);

			String type = name.getKeyProperty("type");
			if (type != null) {
				type = MBeanMap.prettify(type);
				objects = getMap(objects, type);
			}

			String key = name.getKeyProperty("name");
			if (key != null) {
				key = MBeanMap.prettify(key);
				objects = getMap(objects, key);
			}

			for (String property : name.getKeyPropertyList().keySet()) {
				if (property.equals("type") || property.equals("name")) {
					continue;
				}
				key = MBeanMap.prettify(property);
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

	@RequestMapping("/varz/mbeans/domains")
	@ResponseBody
	public Set<String> getMBeanDomains() throws IOException {
		Set<String> result = new HashSet<String>();
		Set<ObjectName> names = server.queryNames(null, null);
		for (ObjectName name : names) {
			result.add(name.getDomain());
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

	private Map<String, String> getHostProperties() {
		Map<String, String> env = new LinkedHashMap<String, String>();
		try {
			Map<String, String> values = System.getenv();
			for (String key : values.keySet()) {
				env.put(key, values.get(key));
			}
		}
		catch (Exception e) {
			logger.warn("Could not obtain OS environment", e);
		}
		return env;
	}

}
