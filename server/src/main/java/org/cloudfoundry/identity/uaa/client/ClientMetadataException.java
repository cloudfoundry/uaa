
package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.error.UaaException;
import org.springframework.http.HttpStatus;

import java.util.Map;

public class ClientMetadataException extends UaaException {

    private final HttpStatus status;
    protected Map<String, Object> extraInfo;

    public ClientMetadataException(String message, Throwable cause, HttpStatus status) {
        super(message, cause);
        this.status = status;
    }

    public ClientMetadataException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }

    public ClientMetadataException(String message, HttpStatus status, Map<String,Object> extraInformation) {
        super(message);
        this.status = status;
        this.extraInfo = extraInformation;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, Object> getExtraInfo() {
        return extraInfo;
    }
}
