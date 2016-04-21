package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.scim.ScimUser;

public interface InvitationsService {

    AcceptedInvitation acceptInvitation(String code, String password);

    void inviteUser(ScimUser user, String currentUser, String clientId, String redirectUri);

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
