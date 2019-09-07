package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URI;

public class LoggerContextCleanupExtension implements BeforeAllCallback, AfterAllCallback {

    @Override
    public void beforeAll(ExtensionContext context) {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);

        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
        store.put("configLocation", loggerContext.getConfigLocation());
    }

    @Override
    public void afterAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));
        URI configLocation = store.get("configLocation", URI.class);

        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        loggerContext.setConfigLocation(configLocation);
    }

}
