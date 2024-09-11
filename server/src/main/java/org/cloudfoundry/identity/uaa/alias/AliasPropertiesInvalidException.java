package org.cloudfoundry.identity.uaa.alias;

public class AliasPropertiesInvalidException extends RuntimeException {
    public AliasPropertiesInvalidException() {
        super("The fields 'aliasId' and/or 'aliasZid' are invalid.");
    }
}
