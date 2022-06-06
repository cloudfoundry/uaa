package org.cloudfoundry.identity.uaa.ratelimiting.core.http;

/**
 * Implementations will return the CallerID type requested OR <code>null</code> if requested type does not exist!
 */
public interface CallerIdSupplierByType {
    /**
     * @return null if Caller did not provide Credentials or a string form of the Credentials
     */
    String getCallerCredentialsID();

    /**
     * @return null if Caller did not provide a RemoteAddress or a string form of the RemoteAddress
     */
    String getCallerRemoteAddressID();
}
