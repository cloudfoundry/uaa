package org.cloudfoundry.identity.uaa.error;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2ExceptionJackson2Serializer;

/**
 * @author Dave Syer
 *
 */
public class UaaExceptionSerializer extends OAuth2ExceptionJackson2Serializer {

    public UaaExceptionSerializer() {
        super(UaaExceptionSerializer.class);
    }
}
