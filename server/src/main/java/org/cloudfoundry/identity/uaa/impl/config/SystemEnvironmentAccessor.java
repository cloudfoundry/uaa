package org.cloudfoundry.identity.uaa.impl.config;

/**
 * Interface that by default reads environments directly from the
 * {@link System#getenv(String)} method.
 * Can be overridden when you wish to access these values from elsewhere.
 */
public interface SystemEnvironmentAccessor {
    default String getEnvironmentVariable(String name) {
        return System.getenv(name);
    }
}
