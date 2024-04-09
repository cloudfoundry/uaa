package org.cloudfoundry.identity.uaa.alias;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class EntityAliasFailedException extends UaaException {
    private static final String ERROR = "alias_entity_creation_failed";

    public EntityAliasFailedException(
            final String msg,
            final int httpStatusCode,
            final Throwable cause
    ) {
        super(cause, ERROR, msg, httpStatusCode);
    }
}
