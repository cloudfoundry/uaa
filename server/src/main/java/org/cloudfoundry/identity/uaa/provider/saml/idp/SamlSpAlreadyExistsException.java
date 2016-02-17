package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.error.UaaException;

public class SamlSpAlreadyExistsException extends UaaException {

    /**
     * Serialization id
     */
    private static final long serialVersionUID = -6544686748746941568L;

    public SamlSpAlreadyExistsException(String msg) {
        super("sp_exists", msg, 409);
    }
}
