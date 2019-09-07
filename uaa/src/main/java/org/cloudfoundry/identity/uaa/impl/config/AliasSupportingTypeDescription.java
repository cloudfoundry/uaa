package org.cloudfoundry.identity.uaa.impl.config;

import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.introspector.Property;

import java.util.HashMap;
import java.util.Map;

/**
 * Created by taitz.
 */
class AliasSupportingTypeDescription extends TypeDescription {

    private final Map<String, Property> aliases = new HashMap<>();

    AliasSupportingTypeDescription(Class<?> clazz) {
        super(clazz);
    }

    @Override
    public Property getProperty(String name) {
        return aliases.containsKey(name) ? aliases.get(name) : super.getProperty(name);
    }

    public void put(String alias, Property property) {
        aliases.put(alias, property);
    }

}
