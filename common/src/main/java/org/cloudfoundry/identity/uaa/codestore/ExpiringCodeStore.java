package org.cloudfoundry.identity.uaa.codestore;

import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;

public interface ExpiringCodeStore {

    /**
     * Generate and persist a one-time code with an expiry date.
     *
     * @param data JSON object to be associated with the code
     * @return code
     * @throws java.lang.NullPointerException if data or expiresAt is null
     * @throws java.lang.IllegalArgumentException if expiresAt is in the past
     */
    public ExpiringCode generateCode(String data, Timestamp expiresAt);

    /**
     * Retrieve a code and delete it if it exists.
     *
     * @param code
     * @return code or null if the code is not found
     * @throws java.lang.NullPointerException if the code is null
     */
    public ExpiringCode retrieveCode(String code);

    /**
     * Set the code generator for this store.
     *
     * @param generator Code generator
     */
    public void setGenerator(RandomValueStringGenerator generator);
}
