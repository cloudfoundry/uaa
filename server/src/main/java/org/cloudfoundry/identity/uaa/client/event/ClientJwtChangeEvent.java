package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

public class ClientJwtChangeEvent extends AbstractClientAdminEvent {

    public ClientJwtChangeEvent(ClientDetails client, Authentication principal, String zoneId) {
        super(client, principal, zoneId);
    }

    @Override
    public AuditEventType getAuditEventType() {
        return AuditEventType.ClientJwtChangeSuccess;
    }

}
