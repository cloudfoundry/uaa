package org.cloudfoundry.identity.uaa.extensions;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

public class PollutionPreventionExtension implements AfterAllCallback, BeforeAllCallback {

    @Override
    public void beforeAll(ExtensionContext extensionContext) {
        TestUtils.restoreToDefaults(getApplicationContextOrNull(extensionContext));
    }

    @Override
    public void afterAll(ExtensionContext extensionContext) {
        TestUtils.restoreToDefaults(getApplicationContextOrNull(extensionContext));
    }

    private ApplicationContext getApplicationContextOrNull(ExtensionContext extensionContext) {
        try {
            return SpringExtension.getApplicationContext(extensionContext);
        } catch (IllegalStateException ignore) {
        }
        return null;
    }
}
