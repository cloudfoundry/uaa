package org.cloudfoundry.identity.uaa.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Returns Log instance that replaces \n, \r, \t with a | to prevent log forging.
 */
public class SanitizedLogFactory {

    public static SanitizedLog getLog(Class<?> clazz) {
        return new SanitizedLog(LoggerFactory.getLogger(clazz));
    }

    public static class SanitizedLog {
        private Logger fallback;

        public SanitizedLog(Logger logger) {
            this.fallback = logger;
        }

        public boolean isDebugEnabled() {
            return fallback.isDebugEnabled();
        }

        public void info(String message) {
            fallback.info(LogSanitizerUtil.sanitize(message));
        }

        public void warn(String message) {
            fallback.warn(LogSanitizerUtil.sanitize(message));
        }

        public void debug(String message) {
            fallback.debug(LogSanitizerUtil.sanitize(message));
        }

        public void debug(String message, Throwable t) {
            fallback.debug(LogSanitizerUtil.sanitize(message), t);
        }
    }
}