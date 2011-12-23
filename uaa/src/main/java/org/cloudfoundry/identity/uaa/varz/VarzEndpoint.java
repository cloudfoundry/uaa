package org.cloudfoundry.identity.uaa.varz;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanServer;
import javax.management.ObjectName;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;


@Controller
public class VarzEndpoint {

	private MBeanServer server;
	
	private Map<String,Object> statix = new LinkedHashMap<String, Object>();
	
	public void setStaticValues(Map<String, Object> statics) {
		this.statix = new LinkedHashMap<String, Object>(statics);
	}

	public void setServer(MBeanServer server) {
		this.server = server;
	}

	@RequestMapping("/varz")
	@ResponseBody
	public Map<String, ?> getVarz()
			throws Exception {
		Map<String, Object> result = new LinkedHashMap<String, Object>(statix);
		result.putAll(getMBeans("java.lang:*"));
		result.putAll(getMBeans("Catalina:type=GlobalRequestProcessor,*"));
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
	public Set<String> getMBeanDomains() {
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

}
