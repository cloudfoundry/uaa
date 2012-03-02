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
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.expression.MapAccessor;
import org.springframework.core.env.Environment;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class VarzEndpoint implements EnvironmentAware {

	private static Log logger = LogFactory.getLog(VarzEndpoint.class);

	private MBeanServerConnection server;

	private Map<String, Object> statix = new LinkedHashMap<String, Object>();

	private Environment environment;
	
	private String baseUrl;
	
	/**
	 * Hard-coded baseUrl for absolute links.
	 * @param baseUrl the baseUrl to set
	 */
	public void setBaseUrl(String baseUrl) {
		this.baseUrl = baseUrl;
	}

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
	public Map<String, ?> getVarz(@ModelAttribute("baseUrl") String baseUrl) throws Exception {

		Map<String, Object> result = new LinkedHashMap<String, Object>(statix);
		result.put("domains", getLinks(baseUrl, getMBeanDomains()));
		result.put("env", getLink(baseUrl, "env"));

		Map<String, ?> memory = pullUpMap("java.lang", "type=Memory");
		result.put("mem", getValueFromMap(memory, "memory.heap_memory_usage.used"));
		result.put("memory", getValueFromMap(memory, "memory"));

		Map<String, ?> spring = pullUpMap("spring.application", "*");
		if (spring != null) {
			// Information about tokens (counts etc)
			putIfNotNull(result, "token_store", getValueFromMap(spring, "#this['token_store']?.token_store"));
			// Information about audit (counts)
			putIfNotNull(result, "audit_service", getValueFromMap(spring, "#this['logging_audit_service']?.logging_audit_service"));
		}
		if (environment != null) {
			result.put("spring.profiles.active", environment.getActiveProfiles());
		}
		return result;
	}

	private Map<String,String> getLinks(String baseUrl, Collection<String> paths) {
		Map<String,String> map = new LinkedHashMap<String, String>();
		for (String domain : paths) {
			map.put(domain, getLink(baseUrl, domain));
		}
		return map;
	}

	private String getLink(String baseUrl, String path) {
		String url = path;
		if (url.endsWith("/")) {
			url = url.substring(0, url.lastIndexOf("/"));
		}
		return String.format("%s/varz/%s", baseUrl, path);
	}

	/**
	 * Compute a base url for links.
	 * 
	 * @param request the current request
	 * @return a computed base url for this application, or the hard-coded {@link #setBaseUrl(String) value} if set
	 */
	@ModelAttribute("baseUrl")
	public String getBaseUrl(HttpServletRequest request) {
		if (this.baseUrl!=null) {
			return this.baseUrl;
		}
		String scheme = request.getScheme();
		StringBuffer url = new StringBuffer(scheme + "://");
		url.append(request.getServerName());
		int port = request.getServerPort();
		if ((scheme.equals("http") && port != 80) || (scheme.equals("https") && port != 443)) {
			url.append(":" + port);
		}
		url.append(request.getContextPath());
		return url.toString();
	}

	private void putIfNotNull(Map<String, Object> result, String key, Object value) {
		if (value!=null) {
			result.put(key, value);
		}
	}

	private Map<String, ?> pullUpMap(String domain, String pattern) throws Exception {
		@SuppressWarnings("unchecked")
		Map<String, ?> map = (Map<String, ?>) getMBeans(domain, pattern).get(domain);
		return map == null ? Collections.<String, Object>emptyMap() : map;
	}

	private Object getValueFromMap(Map<String, ?> map, String path) throws Exception {
		@SuppressWarnings("unchecked")
		MapWrapper wrapper = new MapWrapper((Map<String, Object>) map);
		return wrapper.get(path);
	}

	@RequestMapping("/varz/env")
	@ResponseBody
	public Map<String, ?> getEnv() throws Exception {
		Map<String, Object> result = new LinkedHashMap<String, Object>(statix);
		result.putAll(getHostProperties());
		if (environment != null) {
			result.put("spring.profiles.active", environment.getActiveProfiles());
		}
		return result;
	}

	@RequestMapping("/varz/domains/{domain}")
	@ResponseBody
	public Map<String, ?> getDomain(@PathVariable String domain,
			@RequestParam(required = false, defaultValue = "*") String pattern) throws Exception {

		Map<String, Object> result = new LinkedHashMap<String, Object>();

		// Prevent known stack overflows introspecting tomcat mbeans
		if (domain.equals("Catalina") || domain.equals("*") || domain.equals("tomcat")) {
			if (!pattern.contains("type=")) {
				pattern = "type=GlobalRequestProcessor," + pattern;
			}
			result.putAll(getMBeans("Catalina", "*"));
			Map<String, ?> tomcat = getMBeans("*", "type=GlobalRequestProcessor,*");
			if (!tomcat.isEmpty()) {
				if (tomcat.size() == 1) {
					// tomcat 6.0.23, 6.0.35 have different default domains so normalize...
					@SuppressWarnings("unchecked")
					Map<String, ?> map = (Map<String, ?>) tomcat.values().iterator().next();
					result.putAll(map);
				}
				else {
					result.putAll(tomcat);
				}
			}
		}
		else {
			result.putAll(getMBeans(domain, pattern));
		}

		return result;
	}

	private Map<String, ?> getMBeans(String domain, String pattern) throws Exception {
		Set<ObjectName> names = server.queryNames(ObjectName.getInstance(domain + ":" + pattern), null);

		Map<String, Object> result = new LinkedHashMap<String, Object>();

		for (ObjectName name : names) {

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

	@RequestMapping("/varz/domains")
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

	class MapWrapper {

		private final SpelExpressionParser parser;

		private final StandardEvaluationContext context;

		private final Map<String, Object> target;

		public MapWrapper(Map<String, Object> target) throws Exception {
			this.target = target;
			context = new StandardEvaluationContext();
			context.addPropertyAccessor(new MapAccessor());
			parser = new SpelExpressionParser();
		}

		public Map<String, Object> getMap() {
			return target;
		}

		public Object get(String expression) throws Exception {
			return get(expression, Object.class);
		}

		public <T> T get(String expression, Class<T> type) throws Exception {
			return parser.parseExpression(expression).getValue(context, target, type);
		}

		@Override
		public String toString() {
			return target.toString();
		}

	}
}
