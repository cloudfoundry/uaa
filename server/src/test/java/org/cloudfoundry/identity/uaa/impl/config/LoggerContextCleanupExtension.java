package org.cloudfoundry.identity.uaa.impl.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import java.net.URI;

public class LoggerContextCleanupExtension implements BeforeAllCallback, AfterAllCallback {

    private URI configLocation = null;

    @Override
    public void beforeAll(ExtensionContext context) {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        configLocation = loggerContext.getConfigLocation();
    }

    @Override
    public void afterAll(ExtensionContext context) {
        LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
        loggerContext.setConfigLocation(configLocation);
    }

}
