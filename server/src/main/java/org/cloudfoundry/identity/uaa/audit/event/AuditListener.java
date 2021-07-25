package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.springframework.context.ApplicationListener;
import org.springframework.util.Assert;

/**
 * Spring {@code ApplicationListener} which picks up the listens for
 * {@code AbstractUaaEvent}s and passes the relevant
 * information to the {@code UaaAuditService}.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 */
public class AuditListener implements ApplicationListener<AbstractUaaEvent> {
    private final UaaAuditService uaaAuditService;

    public AuditListener(UaaAuditService auditor) {
        Assert.notNull(auditor, "[Assertion failed] - auditor is required; it must not be null");
        this.uaaAuditService = auditor;
    }

    @Override
    public void onApplicationEvent(AbstractUaaEvent event) {
        event.process(uaaAuditService);
    }

}
