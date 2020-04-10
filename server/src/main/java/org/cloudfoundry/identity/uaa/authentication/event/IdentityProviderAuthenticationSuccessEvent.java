package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

public class IdentityProviderAuthenticationSuccessEvent extends AbstractUaaAuthenticationEvent {
    private final UaaUser user;
    private final String authenticationType;

    public IdentityProviderAuthenticationSuccessEvent(UaaUser user, Authentication authentication, String authenticationType, String zoneId) {
        super(authentication, zoneId);
        this.user = user;
        this.authenticationType = authenticationType;
    }

    @Override
    public AuditEvent getAuditEvent() {
        Assert.notNull(user, "UaaUser cannot be null");
        return createAuditRecord(user.getId(), AuditEventType.IdentityProviderAuthenticationSuccess,
                getOrigin(getAuthenticationDetails()), user.getUsername(), authenticationType, null);
    }

    public UaaUser getUser() {
        return user;
    }

    public String getAuthenticationType() { return authenticationType; }

}
