package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class InvitationsResponse {

    @JsonProperty(value = "new_invites")
    private List<Invitee> newInvites = new ArrayList<>();
    @JsonProperty(value = "failed_invites")
    private List<Invitee> failedInvites = new ArrayList<>();

    public InvitationsResponse() {
    }

    public List<Invitee> getNewInvites() {
        return newInvites;
    }

    public void setNewInvites(List<Invitee> newInvites) {
        this.newInvites = newInvites;
    }

    public List<Invitee> getFailedInvites() {
        return failedInvites;
    }

    public void setFailedInvites(List<Invitee> failedInvites) {
        this.failedInvites = failedInvites;
    }

    public static Invitee failure(String email, String errorCode, String errorMessage) {
        Invitee user = new Invitee();
        user.email = email;
        user.errorCode = errorCode;
        user.errorMessage = errorMessage;
        user.success = false;
        return user;
    }

    public static Invitee success(String email, String userId, String origin, URL inviteLink) {
        Invitee user = new Invitee();
        user.email = email;
        user.userId = userId;
        user.origin = origin;
        user.success = true;
        user.inviteLink = inviteLink;
        return user;
    }

    public static class Invitee {
        private String email;
        private String userId;
        private String origin;
        private boolean success;
        private String errorCode;
        private String errorMessage;

        private URL inviteLink;

        public Invitee() {
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

        public URL getInviteLink() {
            return inviteLink;
        }

        public void setInviteLink(URL inviteLink) {
            this.inviteLink = inviteLink;
        }

    }

}
