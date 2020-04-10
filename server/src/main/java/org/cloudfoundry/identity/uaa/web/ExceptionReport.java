

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
