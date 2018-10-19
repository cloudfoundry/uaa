package org.cloudfoundry.identity.uaa.test;

import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class HoneycombAuditEventTestListenerExtension implements BeforeEachCallback {
    @Override
    public void beforeEach(ExtensionContext context) throws Exception {
        HoneycombAuditEventTestListener.testRunning = context.getDisplayName();
    }
}
