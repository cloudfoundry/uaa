package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

public interface RequestInfo extends ServletPathAccessor,
        CallerIdAccessor {
}