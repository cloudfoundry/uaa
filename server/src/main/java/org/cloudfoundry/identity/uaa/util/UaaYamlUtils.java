package org.cloudfoundry.identity.uaa.util;

import org.cloudfoundry.identity.uaa.impl.config.CustomPropertyConstructor;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public final class UaaYamlUtils {

  private UaaYamlUtils() { }

  public static Yaml createYaml() {
    return new Yaml(new SafeConstructor(CustomPropertyConstructor.getDefaultLoaderOptions()));
  }

  public static String dump(Object object) {
    return createYaml().dump(object);
  }
}
