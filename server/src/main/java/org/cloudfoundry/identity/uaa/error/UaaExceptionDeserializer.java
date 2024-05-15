package org.cloudfoundry.identity.uaa.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2ExceptionJackson2Deserializer;

/**
 * @author Dave Syer
 *
 */
public class UaaExceptionDeserializer extends OAuth2ExceptionJackson2Deserializer {

    public UaaExceptionDeserializer() {
        super(UaaExceptionDeserializer.class);
    }
}
