/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Base exception for UAA exceptions.
 *
 * @author Dave Syer
 */
@JsonSerialize(using = UaaExceptionSerializer.class)
@JsonDeserialize(using = UaaExceptionDeserializer.class)
public class UaaException extends RuntimeException {

    private static final String DEFAULT_ERROR = "unknown_error";

    private static final int DEFAULT_STATUS = 400;

    public static final String ERROR = "error";

    public static final String DESCRIPTION = "error_description";

    private static final String STATUS = "status";

    private Map<String, String> additionalInformation = null;

    private final int status;

    private final String error;

    public UaaException(String msg, Throwable t) {
        super(msg, t);
        this.error = DEFAULT_ERROR;
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
        this.error = error;
        this.status = status;
    }

    public UaaException(Throwable cause, String error, String description, int status) {
        super(description, cause);
        this.error = error;
        this.status = status;
    }
    /**
     * The error code.
     *
     * @return The error code.
     */
    public String getErrorCode() {
        return error;
    }

    /**
     * The HTTP status associated with this error.
     *
     * @return The HTTP status associated with this error.
     */
    public int getHttpStatus() {
        return status;
    }

    /**
     * Get any additional information associated with this error.
     *
     * @return Additional information, or null if none.
     */
    public Map<String, String> getAdditionalInformation() {
        return this.additionalInformation;
    }

    /**
     * Add some additional information with this OAuth error.
     *
     * @param key The key.
     * @param value The value.
     */
    public void addAdditionalInformation(String key, String value) {
        if (this.additionalInformation == null) {
            this.additionalInformation = new TreeMap<String, String>();
        }

        this.additionalInformation.put(key, value);

    }

    /**
     * Creates an {@link UaaException} from a Map<String,String>.
     *
     * @param errorParams
     * @return
     */
    public static UaaException valueOf(Map<String, String> errorParams) {
        String errorCode = errorParams.get(ERROR);
        String errorMessage = errorParams.containsKey(DESCRIPTION) ? errorParams.get(DESCRIPTION) : null;
        int status = DEFAULT_STATUS;
        if (errorParams.containsKey(STATUS)) {
            try {
                status = Integer.valueOf(errorParams.get(STATUS));
            } catch (NumberFormatException e) {
                // ignore
            }
        }
        UaaException ex = new UaaException(errorCode, errorMessage, status);
        Set<Map.Entry<String, String>> entries = errorParams.entrySet();
        for (Map.Entry<String, String> entry : entries) {
            String key = entry.getKey();
            if (!ERROR.equals(key) && !DESCRIPTION.equals(key)) {
                ex.addAdditionalInformation(key, entry.getValue());
            }
        }

        return ex;
    }

    @Override
    public String toString() {
        return getSummary();
    }

    /**
     * @return a comma-delimited list of details (key=value pairs)
     */
    public String getSummary() {

        StringBuilder builder = new StringBuilder();

        String delim = "";

        String error = this.getErrorCode();
        if (error != null) {
            builder.append(delim).append("error=\"").append(error).append("\"");
            delim = ", ";
        }

        String errorMessage = this.getMessage();
        if (errorMessage != null) {
            builder.append(delim).append("error_description=\"").append(errorMessage).append("\"");
            delim = ", ";
        }

        Map<String, String> additionalParams = this.getAdditionalInformation();
        if (additionalParams != null) {
            for (Map.Entry<String, String> param : additionalParams.entrySet()) {
                builder.append(delim).append(param.getKey()).append("=\"").append(param.getValue()).append("\"");
                delim = ", ";
            }
        }

        return builder.toString();

    }
}
