package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;

public class UaaLoginHint {
    private String origin;

    public static UaaLoginHint parseRequestParameter(String loginHint) {
        if (loginHint == null) {
            return null;
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            loginHint = URLDecoder.decode(loginHint, "UTF-8");
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
