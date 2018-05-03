package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

public class UaaLoginHint {
    private String origin;

    public static UaaLoginHint parseRequestParameter(String loginHint) {
        if (loginHint == null) {
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.readValue(loginHint, UaaLoginHint.class);
        } catch (IOException e) {
            return null;
        }
    }

    private UaaLoginHint() {
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }
}
