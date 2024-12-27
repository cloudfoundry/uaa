package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

public class UaaLoginHint implements Serializable {
    @Serial
    private static final long serialVersionUID = 4021539346161285037L;
    private String origin;
    private static ObjectMapper mapper = new ObjectMapper();

    public static UaaLoginHint parseRequestParameter(String loginHint) {
        if (loginHint == null) {
            return null;
        }
        try {
            loginHint = URLDecoder.decode(loginHint, StandardCharsets.UTF_8);
            return mapper.readValue(loginHint, UaaLoginHint.class);
        } catch (IOException e) {
            return null;
        }
    }

    private UaaLoginHint() {
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
