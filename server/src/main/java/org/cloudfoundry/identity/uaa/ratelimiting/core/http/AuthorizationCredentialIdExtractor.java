package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

public interface AuthorizationCredentialIdExtractor {
    /**
     * @return null if Caller did not provide Credentials or a string form of the Credentials
     */
    String mapAuthorizationToCredentialsID(RequestInfo info);

    default String getDescription() {
        return "None";
    }
}
