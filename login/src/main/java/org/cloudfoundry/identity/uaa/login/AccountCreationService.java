package org.cloudfoundry.identity.uaa.login;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

import java.io.IOException;

public interface AccountCreationService {
    void beginActivation(String email, String password, String clientId);

    AccountCreationResponse completeActivation(String code) throws IOException;

    void resendVerificationCode(String email, String clientId);

    ScimUser createUser(String username, String password);

    public static class ExistingUserResponse {
        @JsonProperty
        private String error;

        @JsonProperty
        private String message;

        @JsonProperty("user_id")
        private String userId;

        @JsonProperty
        private Boolean verified;

        @JsonProperty
        private Boolean active;

        public String getError() {
            return error;
        }

        public void setError(String error) {
            this.error = error;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public Boolean getVerified() {
            return verified;
        }

        public void setVerified(Boolean verified) {
            this.verified = verified;
        }

        public Boolean getActive() {
            return active;
        }

        public void setActive(Boolean active) {
            this.active = active;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }
    }

    public static class AccountCreationResponse {
        @JsonProperty("user_id")
        private String userId;
        private String username;
        private String email;
        @JsonProperty("redirect_location")
        private String redirectLocation;

        public AccountCreationResponse() {}

        public AccountCreationResponse(String userId, String username, String email, String redirectLocation) {
            this.userId = userId;
            this.username = username;
            this.email = email;
            this.redirectLocation = redirectLocation;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public String getRedirectLocation() {
            return redirectLocation;
        }

        public String getEmail() {
            return email;
        }
    }
}
