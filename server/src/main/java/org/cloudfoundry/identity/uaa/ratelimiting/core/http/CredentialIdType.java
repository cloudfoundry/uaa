package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

/**
 * A CredentialIdType to "register" as an acceptable Credential definition to <code>AuthorizationCredentialIdExtractor</code> mapper.
 * <p>
 * A Credential definitions consists of two strings: a <code>key</code> and a <code>keyTypeParameters</code> (configuration
 * parameters appropriate to the registered, by <code>key</code>, <code>CredentialIdType</code>).
 */
public interface CredentialIdType {
    /**
     * The unique Key to identify this CredentialIdType
     */
    String key();

    AuthorizationCredentialIdExtractor factory(String keyTypeParameters);
}
