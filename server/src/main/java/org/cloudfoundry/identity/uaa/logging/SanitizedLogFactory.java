package org.cloudfoundry.identity.uaa.logging;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Returns Log instance that replaces \n, \r, \t with a | to prevent log forging.
 */
public class SanitizedLogFactory {

    public static SanitizedLog getLog(Class<?> clazz) {
        return new SanitizedLog(LogFactory.getLog(clazz));
    }

    public static class SanitizedLog {
        private Log fallback;

        public SanitizedLog(Log log) {
            this.fallback = log;
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