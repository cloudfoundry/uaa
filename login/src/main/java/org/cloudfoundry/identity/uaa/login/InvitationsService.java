package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.scim.ScimUser;

public interface InvitationsService {
    void inviteUser(String email, String currentUser, String clientId, String redirectUri);
    AcceptedInvitation acceptInvitation(String userId, String email, String password, String clientId, String redirectUri, String origin);

    class AcceptedInvitation {
        private final ScimUser user;
        private final String redirectUri;

        public AcceptedInvitation(String redirectUri, ScimUser user) {
            this.redirectUri = redirectUri;
            this.user = user;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public ScimUser getUser() {
            return user;
        }
    }
}
