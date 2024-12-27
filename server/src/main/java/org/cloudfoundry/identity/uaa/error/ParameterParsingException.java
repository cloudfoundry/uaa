package org.cloudfoundry.identity.uaa.error;

public class ParameterParsingException extends UaaException {

    private static final String ERROR_DESCRIPTION = "One of the parameters was incorrectly encoded";

    public ParameterParsingException() {
        super("parameter_parsing_error", ERROR_DESCRIPTION, DEFAULT_STATUS);
    }

}