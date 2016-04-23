/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.impl.config;

import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.NodeId;

import java.beans.IntrospectionException;
import java.util.HashMap;
import java.util.Map;

/**
 * Extended version of snakeyaml's Constructor class to facilitate mapping
 * custom
 * YAML keys to Javabean property names.
 * 
 * @author Luke Taylor
 */
public class CustomPropertyConstructor extends Constructor {
    private final Map<Class<?>, Map<String, Property>> properties = new HashMap<Class<?>, Map<String, Property>>();
    private final PropertyUtils propertyUtils = new PropertyUtils();

    public CustomPropertyConstructor(Class<?> theRoot) {
        super(theRoot);
        yamlClassConstructors.put(NodeId.mapping, new CustomPropertyConstructMapping());
    }

    /**
     * Adds an alias for a Javabean property name on a particular type.
     * The values of YAML keys with the alias name will be mapped to the
     * Javabean
     * property.
     *
     * @param alias the bean property alias
     * @param type the bean property type
     * @param name the bean property name
     */
    protected final void addPropertyAlias(String alias, Class<?> type, String name) {
        Map<String, Property> typeMap = properties.get(type);

        if (typeMap == null) {
            typeMap = new HashMap<String, Property>();
            properties.put(type, typeMap);
        }

        try {
            typeMap.put(alias, propertyUtils.getProperty(type, name));
        } catch (IntrospectionException e) {
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
            Map<String, Property> m = properties.get(type);

            if (m != null) {
                return m.get(name);
            }
            return null;
        }
    }
}
