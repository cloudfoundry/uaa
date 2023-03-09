package org.cloudfoundry.identity.uaa.util;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public final class UaaYamlUtils {

  private UaaYamlUtils() { }

  public static Yaml createYaml() {
    LoaderOptions loaderOptions = new LoaderOptions();
    loaderOptions.setAllowDuplicateKeys(false);
    return new Yaml(new SafeConstructor(loaderOptions));
  }

  public static String dump(Object object) {
    return createYaml().dump(object);
  }
}
