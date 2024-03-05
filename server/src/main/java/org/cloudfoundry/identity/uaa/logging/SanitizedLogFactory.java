package org.coundfoundry.identity.uaa.logging;

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
            setFallback(logger);
        }

        public void setFallback(Logger logger) {
            this.fallback = logger;
        }

        public boolean isDebugEnabled() {
            return fallback.isDebugEnabled();
        }

        public void info(String message) {
            fallback.info(sanitizeLog(message));
        }

        public void info(String message, Throwable t) {
            fallback.info(sanitizeLog(message), t);
        }

        public void warn(String message) {
            fallback.warn(sanitizeLog(message));
        }

        public void warn(String message, Throwable t) {
            fallback.warn(sanitizeLog(message), t);
        }

        public void debug(String message) {
            fallback.debug(sanitizeLog(message));
        }

        public void debug(String message, Throwable t) {
            fallback.debug(sanitizeLog(message), t);
        }

        public void error(String message) {
            fallback.error(sanitizeLog(message));
        }

        public void error(String message, Throwable t) {
            fallback.error(sanitizeLog(message), t);
        }

        public static String sanitizeLog(String message) {
            return LogSanitizerUtil.sanitize(message);
        }
    }
}
