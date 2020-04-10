
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

/**
 * @author Dave Syer
 */
abstract class AbstractUaaPrincipalEvent extends AbstractUaaEvent {

    AbstractUaaPrincipalEvent(UaaAuthenticationDetails details, String zoneId) {
        super(details, zoneId);
    }

    protected String getOrigin(UaaAuthenticationDetails details) {
        return details == null ? "unknown" : details.getOrigin();
    }

    UaaAuthenticationDetails getAuthenticationDetails() {
        return (UaaAuthenticationDetails) source;
    }

}
