package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

public interface CallerIdAccessor {
    String getAuthorizationHeader();

    String getClientIP();
}