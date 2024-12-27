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

package org.cloudfoundry.identity.uaa.web;

import java.util.Map;

/**
 * @author Dave Syer
 * 
 */
public class ExceptionReport {

    protected Map<String, Object> extraInfo;
    private final Exception exception;
    private final boolean trace;

    public ExceptionReport(Exception exception) {
        this(exception, false);
    }

    public ExceptionReport(Exception exception, boolean trace) {
        this.exception = exception;
        this.trace = trace;
    }

    public ExceptionReport(Exception exception, boolean trace, Map<String, Object> extraInfo) {
        this.exception = exception;
        this.trace = trace;
        this.extraInfo = extraInfo;
    }

    public Exception getException() {
        return exception;
    }

    public boolean isTrace() {
        return trace;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }
}
