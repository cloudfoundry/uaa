package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonProperty;

public class PasswordChange {
    public PasswordChange() {}

    public PasswordChange(String userId, String username) {
        this.userId = userId;
        this.username = username;
    }

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("username")
    private String username;

    @JsonProperty("code")
    private String code;

    @JsonProperty("current_password")
    private String currentPassword;

    @JsonProperty("new_password")
    private String newPassword;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }
}
