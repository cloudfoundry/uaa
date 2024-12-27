package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

public class PasswordChange {
    public PasswordChange() {
    }

    public PasswordChange(String userId, String username, Date passwordModifiedTime, String clientId, String redirectUri) {
        this.userId = userId;
        this.username = username;
        this.passwordModifiedTime = passwordModifiedTime;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
    }

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("username")
    private String username;

    @JsonProperty("passwordModifiedTime")
    private Date passwordModifiedTime;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Date getPasswordModifiedTime() {
        return passwordModifiedTime;
    }

    public void setPasswordModifiedTime(Date passwordModifiedTime) {
        this.passwordModifiedTime = passwordModifiedTime;
    }

    public String getClientId() {
        return clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }
}
