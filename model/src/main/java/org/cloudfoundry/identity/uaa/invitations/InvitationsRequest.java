package org.cloudfoundry.identity.uaa.invitations;

/**
 * Created by pivotal on 9/21/15.
 */
public class InvitationsRequest {

    private String[] emails;

    public InvitationsRequest() {
    }

    public InvitationsRequest(String[] emails) {
        this.setEmails(emails);
    }

    public String[] getEmails() {
        return emails;
    }

    public void setEmails(String[] emails) {
        this.emails = emails;
    }
}
