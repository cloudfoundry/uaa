
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

/**
 * Event which indicates that a non-user principal tried to authenticate but was
 * not found.
 * 
 * @author Dave Syer
 */
public class PrincipalNotFoundEvent extends AbstractUaaPrincipalEvent {

    private String name;

    public PrincipalNotFoundEvent(String name, UaaAuthenticationDetails details, String zoneId) {
        super(details, zoneId);
        this.name = name;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(name, AuditEventType.PrincipalNotFound, getOrigin(getAuthenticationDetails()));
    }

}
