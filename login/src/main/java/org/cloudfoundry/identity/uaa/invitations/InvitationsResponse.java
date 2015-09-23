package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class InvitationsResponse {

    @JsonProperty(value="new_invites")
    private List<InvitedUser> newInvites = new ArrayList<>();
    @JsonProperty(value="failed_invites")
    private List<InvitedUser> failedInvites = new ArrayList<>();

    public InvitationsResponse() {}

    public List<InvitedUser> getNewInvites() {
        return newInvites;
    }

    public void setNewInvites(List<InvitedUser> newInvites) {
        this.newInvites = newInvites;
    }

    public List<InvitedUser> getFailedInvites() {
        return failedInvites;
    }

    public void setFailedInvites(List<InvitedUser> failedInvites) {
        this.failedInvites = failedInvites;
    }

    public static InvitedUser failure(String email, String errorCode, String errorMessage) {
        InvitedUser user = new InvitedUser();
        user.email = email;
        user.errorCode = errorCode;
        user.errorMessage = errorMessage;
        user.success = false;
        return user;
    }

    public static InvitedUser success(String email, String userId, String origin) {
        InvitedUser user = new InvitedUser();
        user.email = email;
        user.userId = userId;
        user.origin = origin;
        user.success = true;
        return user;
    }

    public static class InvitedUser {
        private String email;
        private String userId;
        private String origin;
        private boolean success;
        private String errorCode;
        private String errorMessage;

        public InvitedUser() {
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }

        public String getOrigin() {
            return origin;
        }

        public void setOrigin(String origin) {
            this.origin = origin;
        }

        public boolean isSuccess() {
            return success;
        }

        public void setSuccess(boolean success) {
            this.success = success;
        }

        public String getErrorCode() {
            return errorCode;
        }

        public void setErrorCode(String errorCode) {
            this.errorCode = errorCode;
        }

        public String getErrorMessage() {
            return errorMessage;
        }

        public void setErrorMessage(String errorMessage) {
            this.errorMessage = errorMessage;
        }
    }

}
