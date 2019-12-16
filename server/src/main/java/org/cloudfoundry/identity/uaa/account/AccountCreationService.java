package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.scim.ScimUser;

public interface AccountCreationService {
    void beginActivation(String email, String password, String clientId, String redirectUri);

    AccountCreationResponse completeActivation(String code);

    ScimUser createUser(String username, String password, String origin);

    String getDefaultRedirect();

    class AccountCreationResponse {
        @JsonProperty("user_id")
        private String userId;
        private String username;
        private String email;
        @JsonProperty("redirect_location")
        private String redirectLocation;

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
