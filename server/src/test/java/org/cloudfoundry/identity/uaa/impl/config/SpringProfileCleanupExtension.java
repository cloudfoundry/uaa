package org.cloudfoundry.identity.uaa.impl.config;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class SpringProfileCleanupExtension implements BeforeAllCallback, AfterAllCallback {

    private static String activeSpringProfiles;

    @Override
    public void beforeAll(ExtensionContext context) {
        activeSpringProfiles = System.getProperty("spring.profiles.active");
    }

    @Override
    public void afterAll(ExtensionContext context) {
        if (activeSpringProfiles != null) {
            System.setProperty("spring.profiles.active", activeSpringProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

}
