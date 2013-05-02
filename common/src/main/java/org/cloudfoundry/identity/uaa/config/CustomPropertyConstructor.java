package org.cloudfoundry.identity.uaa.config;

import java.beans.IntrospectionException;
import java.util.HashMap;
import java.util.Map;

import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.NodeId;

/**
 * Extended version of snakeyaml's Constructor class to facilitate mapping custom
 * YAML keys to Javabean property names.
 *
 * @author Luke Taylor
 */
public class CustomPropertyConstructor extends Constructor {
	private final Map<Class<?>, Map<String,Property>> properties = new HashMap<Class<?>, Map<String, Property>>();
	private final PropertyUtils propertyUtils = new PropertyUtils();

	public CustomPropertyConstructor(Class<?> theRoot) {
		super(theRoot);
		yamlClassConstructors.put(NodeId.mapping, new CustomPropertyConstructMapping());
	}

	/**
	 * Adds an alias for a Javabean property name on a particular type.
	 * The values of YAML keys with the alias name will be mapped to the Javabean
	 * property.
	 */
	protected final void addPropertyAlias(String alias, Class<?> type, String name) {
		Map<String,Property> typeMap = properties.get(type);

		if (typeMap == null) {
			typeMap = new HashMap<String, Property>();
			properties.put(type, typeMap);
		}

		try {
			typeMap.put(alias, propertyUtils.getProperty(type, name));
		}
		catch (IntrospectionException e) {
			throw new RuntimeException(e);
		}
	}

	class CustomPropertyConstructMapping extends ConstructMapping {

		@Override
		protected Property getProperty(Class<?> type, String name) throws IntrospectionException {
			Property p = lookupProperty(type, name);

			return p != null ? p : super.getProperty(type, name);
		}

		private Property lookupProperty(Class<?> type, String name) {
			Map<String,Property> m = properties.get(type);

			if (m != null) {
				return m.get(name);
			}
			return null;
		}
	}
}
