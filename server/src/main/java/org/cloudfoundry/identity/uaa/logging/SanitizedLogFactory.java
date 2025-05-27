package org.cloudfoundry.identity.uaa.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Returns Log instance that replaces \n, \r, \t with a | to prevent log forging.
 */
public final class SanitizedLogFactory {

    private SanitizedLogFactory() {
    }

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
            if (fallback.isInfoEnabled()) {
                fallback.info(LogSanitizerUtil.sanitize(message));
            }
        }

        public void info(String message, Throwable t) {
            if (fallback.isInfoEnabled()) {
                fallback.info(LogSanitizerUtil.sanitize(message), t);
            }
        }

        public void warn(String message) {
            if (fallback.isWarnEnabled()) {
                fallback.warn(LogSanitizerUtil.sanitize(message));
            }
        }

        public void warn(String message, Throwable t) {
            if (fallback.isWarnEnabled()) {
                fallback.warn(LogSanitizerUtil.sanitize(message), t);
            }
        }

        public void debug(String message) {
            if (fallback.isDebugEnabled()) {
                fallback.debug(LogSanitizerUtil.sanitize(message));
            }
        }

        public void debug(String message, Object... params) {
            if (fallback.isDebugEnabled()) {
                fallback.debug(LogSanitizerUtil.sanitize(message), params);
            }
        }

        public void debug(String message, Throwable t) {
            if (fallback.isDebugEnabled()) {
                fallback.debug(LogSanitizerUtil.sanitize(message), t);
            }
        }

        public void error(String message) {
            if (fallback.isErrorEnabled()) {
                fallback.error(LogSanitizerUtil.sanitize(message));
            }
        }

        public void error(String message, Throwable t) {
            if (fallback.isErrorEnabled()) {
                fallback.error(LogSanitizerUtil.sanitize(message), t);
            }
        }

        public void trace(String message) {
            if (fallback.isTraceEnabled()) {
                fallback.trace(LogSanitizerUtil.sanitize(message));
            }
        }

        public void trace(String message, Throwable t) {
            if (fallback.isTraceEnabled()) {
                fallback.trace(LogSanitizerUtil.sanitize(message), t);
            }
        }
    }
}
