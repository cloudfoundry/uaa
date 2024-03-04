package org.cloudfoundry.identity.uaa.logging;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Returns Log instance that replaces \n, \r, \t with a | to prevent log forging.
 */
public class SanitizedLogFactory {

    private SanitizedLogFactory() {
    }

    public static SanitizedLog getLog(Class<?> clazz) {
        return new SanitizedLog(LogManager.getLogger(clazz));
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
            fallback.info(() -> LogSanitizerUtil.sanitize(message));
        }

        public void warn(String message) {
            fallback.warn(() -> LogSanitizerUtil.sanitize(message));
        }

        public void debug(String message) {
            fallback.debug(() -> LogSanitizerUtil.sanitize(message));
        }

        public void debug(String message, Throwable t) {
            fallback.debug(() -> LogSanitizerUtil.sanitize(message), t);
        }
    }
}