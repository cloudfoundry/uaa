package org.cloudfoundry.identity.uaa.extensions;

import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

public class SystemPropertiesCleanupExtension implements BeforeEachCallback, AfterEachCallback {

    private final Set<String> properties;

    public SystemPropertiesCleanupExtension(String... props) {
        this.properties = Arrays.stream(props).collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));

        properties.forEach(s -> store.put(s, System.getProperty(s)));
    }

    @Override
    public void afterEach(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));

        properties.forEach(key -> {
                    String value = store.get(key, String.class);
                    if (value == null) {
                        System.clearProperty(key);
                    } else {
                        System.setProperty(key, value);
                    }
                }
        );
    }
}
