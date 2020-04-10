package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.springframework.security.core.Authentication;

/** @author Luke Taylor */
public abstract class AbstractUaaAuthenticationEvent extends AbstractUaaEvent {

  AbstractUaaAuthenticationEvent(Authentication authentication, String zoneId) {
    super(authentication, zoneId);
  }

  protected String getOrigin(UaaAuthenticationDetails details) {
    return details == null ? "unknown" : details.toString();
  }

  UaaAuthenticationDetails getAuthenticationDetails() {
    return (UaaAuthenticationDetails) getAuthentication().getDetails();
  }
}
