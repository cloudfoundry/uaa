package org.cloudfoundry.identity.uaa.extensions;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class SpringProfileCleanupExtension implements BeforeAllCallback, AfterAllCallback {

    @Override
    public void beforeAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
        store.put("spring.profiles.active", System.getProperty("spring.profiles.active"));
    }

    @Override
    public void afterAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
        String activeSpringProfiles = store.get("spring.profiles.active", String.class);

        if (activeSpringProfiles != null) {
            System.setProperty("spring.profiles.active", activeSpringProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

}
