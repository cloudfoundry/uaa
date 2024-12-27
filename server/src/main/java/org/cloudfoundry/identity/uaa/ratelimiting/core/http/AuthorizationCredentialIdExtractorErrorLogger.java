package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

public interface AuthorizationCredentialIdExtractorErrorLogger {
    void log(Exception e);
}
