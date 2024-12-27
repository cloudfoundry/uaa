package org.cloudfoundry.identity.uaa.oauth.pkce;

import java.io.Serial;

/**
 * Universal PKCE Validation Service exception
 * 
 * @author Zoltan Maradics
 *
 */
public class PkceValidationException extends Exception {

    @Serial
    private static final long serialVersionUID = 7887667018613362856L;

    public PkceValidationException(String msg) {
        super(msg);
    }

}
