/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;

public interface ExpiringCodeStore {

    /**
     * Generate and persist a one-time code with an expiry date.
     *
     * @param data JSON object to be associated with the code
     * @param intent An optional key (not necessarily unique) for looking up codes
     * @param zoneId
     * @return code the generated one-time code
     * @throws java.lang.NullPointerException if data or expiresAt is null
     * @throws java.lang.IllegalArgumentException if expiresAt is in the past
     */
    ExpiringCode generateCode(String data, Timestamp expiresAt, String intent, String zoneId);

    /**
     * Retrieve a code BUT DO NOT DELETE IT.
     *
     * WARNING - if you intend to expire the code as soon as you read it,
     * use {@link #retrieveCode(String, String)} instead.
     *
     * @param code the one-time code to look for
     * @param zoneId
     * @return code or null if the code is not found
     * @throws java.lang.NullPointerException if the code is null
     */
    ExpiringCode peekCode(String code, String zoneId);

    /**
     * Retrieve a code and delete it if it exists.
     *
     * @param code the one-time code to look for
     * @param zoneId
     * @return code or null if the code is not found
     * @throws java.lang.NullPointerException if the code is null
     */
    ExpiringCode retrieveCode(String code, String zoneId);

    /**
     * Set the code generator for this store.
     *
     * @param generator Code generator
     */
    void setGenerator(RandomValueStringGenerator generator);

    /**
     * Remove all codes matching a given intent.
     *
     * @param intent Intent of codes to remove
     * @param zoneId
     */
    void expireByIntent(String intent, String zoneId);
}
