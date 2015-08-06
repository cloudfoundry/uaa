package org.cloudfoundry.identity.uaa.scim.endpoints;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

@JsonIgnoreProperties(ignoreUnknown = true)
public class PasswordChange {
    public PasswordChange() {}

    public PasswordChange(String userId, String username, Date passwordModifiedTime) {
        this.userId = userId;
        this.username = username;
        this.passwordModifiedTime = passwordModifiedTime;
    }

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("username")
    private String username;

    @JsonProperty("passwordModifiedTime")
    private Date passwordModifiedTime;

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
}
