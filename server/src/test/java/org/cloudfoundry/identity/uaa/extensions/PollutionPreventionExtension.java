package org.cloudfoundry.identity.uaa.extensions;

import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.sql.SQLException;

public class PollutionPreventionExtension implements AfterAllCallback, BeforeAllCallback {

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws SQLException {
        TestUtils.restoreToDefaults(getApplicationContextOrNull(extensionContext));
    }

    @Override
    public void afterAll(ExtensionContext extensionContext) throws SQLException {
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
