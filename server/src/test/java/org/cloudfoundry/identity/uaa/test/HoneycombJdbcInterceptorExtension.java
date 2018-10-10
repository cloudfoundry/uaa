package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class HoneycombJdbcInterceptorExtension implements BeforeEachCallback {
    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        HoneycombJdbcInterceptor.testRunning = context.getDisplayName();
    }
}
