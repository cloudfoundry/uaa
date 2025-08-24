package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

public class ClientJwtFailureEvent extends AbstractClientAdminEvent {

    private String message;

    public ClientJwtFailureEvent(String message, Authentication principal) {
        this(message, null, principal, IdentityZoneHolder.getCurrentZoneId());
    }

    public ClientJwtFailureEvent(String message, ClientDetails client, Authentication principal, String zoneId) {
        super(client, principal, zoneId);
        this.message = message;
    }

    @Override
    public AuditEventType getAuditEventType() {
        return AuditEventType.ClientJwtChangeFailure;
    }

}
