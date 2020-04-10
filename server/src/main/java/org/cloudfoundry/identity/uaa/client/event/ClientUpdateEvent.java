

package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;

public class ClientUpdateEvent extends AbstractClientAdminEvent {

    public ClientUpdateEvent(ClientDetails client, Authentication principal, String zoneId) {
        super(client, principal, zoneId);
    }

    @Override
    public AuditEventType getAuditEventType() {
        return AuditEventType.ClientUpdateSuccess;
    }

}
