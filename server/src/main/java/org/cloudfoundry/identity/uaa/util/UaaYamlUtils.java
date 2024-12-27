package org.cloudfoundry.identity.uaa.util;

import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public final class UaaYamlUtils {

    private UaaYamlUtils() {
    }

    public static Yaml createYaml() {
        return new Yaml(new SafeConstructor(getDefaultLoaderOptions()));
    }

    public static String dump(Object object) {
        return createYaml().dump(object);
    }

    public static LoaderOptions getDefaultLoaderOptions() {
        LoaderOptions loaderOptions = new LoaderOptions();
        loaderOptions.setAllowDuplicateKeys(false);
        return loaderOptions;
    }

    public static DumperOptions getDefaultDumperOptions() {
        DumperOptions dump = new DumperOptions();
        dump.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        dump.setPrettyFlow(true);
        dump.setIndent(2);
        dump.setCanonical(false);
        dump.setExplicitStart(true);
        return dump;
    }
}
