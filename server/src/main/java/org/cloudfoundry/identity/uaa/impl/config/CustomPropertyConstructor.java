package org.cloudfoundry.identity.uaa.impl.config;

import java.util.HashMap;
import java.util.Map;
import org.springframework.util.Assert;
import org.yaml.snakeyaml.TypeDescription;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.introspector.Property;
import org.yaml.snakeyaml.introspector.PropertyUtils;
import org.yaml.snakeyaml.nodes.NodeId;

/**
 * Extended version of snakeyaml's Constructor class to facilitate mapping custom YAML keys to
 * Javabean property names.
 *
 * @author Luke Taylor
 */
public class CustomPropertyConstructor extends Constructor {

  private final Map<Class<?>, Map<String, Property>> properties =
      new HashMap<Class<?>, Map<String, Property>>();
  private final PropertyUtils propertyUtils = new PropertyUtils();
  private final Map<Class<?>, AliasSupportingTypeDescription> typeDescriptions = new HashMap<>();

  public CustomPropertyConstructor(Class<?> theRoot) {
    super(theRoot);
    TypeDescription typeDescription = createTypeDescription(theRoot);
    addTypeDescription(typeDescription);
    yamlClassConstructors.put(NodeId.mapping, new CustomPropertyConstructMapping());
  }

  TypeDescription createTypeDescription(Class<?> clazz) {
    Assert.isTrue(
        !typeDescriptions.containsKey(clazz),
        "type description for " + clazz.getSimpleName() + " already exists");
    AliasSupportingTypeDescription typeDescription = new AliasSupportingTypeDescription(clazz);
    typeDescriptions.put(clazz, typeDescription);
    return typeDescription;
  }

  /**
   * Adds an alias for a Javabean property name on a particular type. The values of YAML keys with
   * the alias name will be mapped to the Javabean property.
   *
   * @param alias the bean property alias
   * @param type the bean property type
   * @param name the bean property name
   */
  protected final void addPropertyAlias(String alias, Class<?> type, String name) {
    Map<String, Property> typeMap = properties.computeIfAbsent(type, k -> new HashMap<>());

    Property property = propertyUtils.getProperty(type, name);
    typeMap.put(alias, property);
    addAliasToTypeDescription(alias, type, property);
  }

  private void addAliasToTypeDescription(String alias, Class<?> type, Property property) {
    AliasSupportingTypeDescription typeDescription = typeDescriptions.get(type);
    if (typeDescription != null) {
      typeDescription.put(alias, property);
    }
  }

  class CustomPropertyConstructMapping extends ConstructMapping {

    @Override
    protected Property getProperty(Class<?> type, String name) {
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
