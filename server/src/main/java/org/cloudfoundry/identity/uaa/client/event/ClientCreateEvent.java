

package org.cloudfoundry.identity.uaa.client.event;

import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;

public class ClientCreateEvent extends AbstractClientAdminEvent {

    public ClientCreateEvent(ClientDetails client, Authentication principal, String zoneId) {
        super(client, principal, zoneId);
    }

    @Override
    AuditEventType getAuditEventType() {
        return AuditEventType.ClientCreateSuccess;
    }
}
