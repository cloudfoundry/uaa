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
package org.cloudfoundry.identity.uaa.error;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;

import java.util.Map;

/**
 * Base exception for UAA exceptions.
 *
 * @author Dave Syer
 */
@JsonSerialize(using = UaaExceptionSerializer.class)
@JsonDeserialize(using = UaaExceptionDeserializer.class)
public class UaaException extends OAuth2Exception {

    private static final String DEFAULT_ERROR = "unknown_error";

    static final int DEFAULT_STATUS = 400;

    private static final String STATUS_STRING = "status";

    private final int status;

    private final String errorString;

    public UaaException(String msg, Throwable t) {
        super(msg, t);
        this.errorString = DEFAULT_ERROR;
        this.status = DEFAULT_STATUS;
    }

    public UaaException(String msg) {
        this(DEFAULT_ERROR, msg, 400);
    }

    public UaaException(String msg, int status) {
        this(DEFAULT_ERROR, msg, status);
    }

    public UaaException(String error, String description, int status) {
        super(description);
        this.errorString = error;
        this.status = status;
    }

    public UaaException(Throwable cause, String error, String description, int status) {
        super(description, cause);
        this.errorString = error;
        this.status = status;
    }

    /**
     * The error code.
     *
     * @return The error code.
     */
    public String getErrorCode() {
        return errorString;
    }

    /**
     * The HTTP status associated with this error.
     *
     * @return The HTTP status associated with this error.
     */
    public int getHttpStatus() {
        return status;
    }

    @Override
    public String getOAuth2ErrorCode() {
        return getErrorCode();
    }


    /**
     * Creates an {@link UaaException} from a {@link Map}.
     *
     * @param errorParams a map with additional error information
     * @return the exception with error information
     */
    public static UaaException valueOf(Map<String, String> errorParams) {
        String errorCode = errorParams.get(ERROR);
        String errorMessage = errorParams.getOrDefault(DESCRIPTION, null);
        int status = DEFAULT_STATUS;
        if (errorParams.containsKey(STATUS_STRING)) {
            try {
                status = Integer.valueOf(errorParams.get(STATUS_STRING));
            } catch (NumberFormatException e) {
                // ignore
            }
        }
        UaaException ex = new UaaException(errorCode, errorMessage, status);
        addAdditionalInformation(ex, errorParams);
        return ex;
    }
}
