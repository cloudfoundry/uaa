package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serializable;
import java.net.URLDecoder;

public class UaaLoginHint implements Serializable {
    private String origin;
    private static ObjectMapper mapper = new ObjectMapper();

    public static UaaLoginHint parseRequestParameter(String loginHint) {
        if (loginHint == null) {
            return null;
        }
        try {
            loginHint = URLDecoder.decode(loginHint, "UTF-8");
            return mapper.readValue(loginHint, UaaLoginHint.class);
        } catch (IOException e) {
            return null;
        }
    }

    public UaaLoginHint() {
    }

    public UaaLoginHint(String origin) {
        this.origin = origin;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    @Override
    public String toString() {
        try {
            return mapper.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return super.toString();
        }
    }
}
