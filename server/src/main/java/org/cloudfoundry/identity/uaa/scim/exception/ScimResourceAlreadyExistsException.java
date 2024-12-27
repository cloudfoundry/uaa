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
package org.cloudfoundry.identity.uaa.scim.exception;

import org.springframework.http.HttpStatus;

import java.util.Map;

/**
 * Unchecked exception signalling that a user account already exists.
 * 
 * @author Dave Syer
 * 
 */
public class ScimResourceAlreadyExistsException extends ScimException {

    /**
     * @param message a message for the caller
     */
    public ScimResourceAlreadyExistsException(String message) {
        super(message, HttpStatus.CONFLICT);
    }

    public ScimResourceAlreadyExistsException(String message, Map<String, Object> extraInformation) {
        super(message, HttpStatus.CONFLICT, extraInformation);
    }

}
