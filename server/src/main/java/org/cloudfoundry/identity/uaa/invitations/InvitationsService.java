package org.cloudfoundry.identity.uaa.invitations;

public interface InvitationsService {

    AcceptedInvitation acceptInvitation(String code, String password);

}
