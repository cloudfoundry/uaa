package org.cloudfoundry.identity.uaa.authentication;

import com.fasterxml.jackson.annotation.JsonProperty;

public class NonStringPassword {
    private final char[] password;

    public NonStringPassword(String password) {
        this.password = password == null ? null : password.toCharArray();
    }

    @JsonProperty("password")
    public String getPassword() {
        return password == null ? null : new String(password);
    }
}
