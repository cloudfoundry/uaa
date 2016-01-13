package org.cloudfoundry.identity.uaa.oauth;


import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.client.http.OAuth2ErrorHandler;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;

public class UaaOauth2ErrorHandler extends  OAuth2ErrorHandler {

    public HttpStatus.Series getErrorAtLevel() {
        return errorAtLevel;
    }

    public void setErrorAtLevel(HttpStatus.Series errorAtLevel) {
        this.errorAtLevel = errorAtLevel;
    }

    private HttpStatus.Series errorAtLevel = HttpStatus.Series.SERVER_ERROR;

    public UaaOauth2ErrorHandler(OAuth2ProtectedResourceDetails resource) {
        super(resource);
    }

    public UaaOauth2ErrorHandler(OAuth2ProtectedResourceDetails resource, HttpStatus.Series errorLevel) {
        this(resource);
        setErrorAtLevel(errorLevel);
    }

    @Override
    public boolean hasError(ClientHttpResponse response) throws IOException {
        return errorAtLevel.value() - response.getStatusCode().series().value() <= 0;
    }
}
