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
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimException extends RuntimeException {

    private final HttpStatus status;
    protected Map<String, Object> extraInfo;

    public ScimException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
    }

    public ScimException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public ScimException(String message, HttpStatus status, Map<String,Object> extraInformation) {
        super(message);
        this.status = status;
        this.extraInfo = extraInformation;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }
}
