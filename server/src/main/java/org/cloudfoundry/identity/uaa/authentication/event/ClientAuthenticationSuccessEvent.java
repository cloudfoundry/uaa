
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.springframework.security.core.Authentication;

public class ClientAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent{

    private String clientId;

    public ClientAuthenticationSuccessEvent(Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        clientId = getAuthenticationDetails().getClientId();
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(clientId, AuditEventType.ClientAuthenticationSuccess,
                getOrigin(getAuthenticationDetails()), "Client authentication success");
    }

    public String getClientId() {
        return clientId;
    }
}
