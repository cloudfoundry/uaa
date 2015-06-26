package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordReset {
    private String code;
    @JsonProperty("new_password") private String newPassword;

    public PasswordReset() { }

    public PasswordReset(String code, String newPassword) {
        this.code = code;
        this.newPassword = newPassword;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
