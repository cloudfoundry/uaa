package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

/**
 * Implementations will return the CallerID type requested OR <code>null</code> if requested type does not exist!
 */
public interface CallerIdSupplierByType {
    /**
     * @return string form of the extract Credentials -- null if Caller did not provide Credentials or there was an error extracting the Credentials
     */
    String getCallerCredentialsID();

    /**
     * @return string form of the RemoteAddress -- while, in theory, there might not be a RemoteAddress (and null would be returned); in practice, there should always be one!
     */
    String getCallerRemoteAddressID();
}
