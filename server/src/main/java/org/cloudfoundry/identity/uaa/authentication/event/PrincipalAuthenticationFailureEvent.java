package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

/**
 * Event which indicates that a non-user principal tried to authenticate and failed.
 *
 * @author Dave Syer
 */
public class PrincipalAuthenticationFailureEvent extends AbstractUaaPrincipalEvent {

  private String name;

  public PrincipalAuthenticationFailureEvent(
      String name, UaaAuthenticationDetails details, String zoneId) {
    super(details == null ? UaaAuthenticationDetails.UNKNOWN : details, zoneId);
    this.name = name;
  }

  @Override
  public AuditEvent getAuditEvent() {
    return createAuditRecord(
        name, AuditEventType.PrincipalAuthenticationFailure, getOrigin(getAuthenticationDetails()));
  }

  public String getName() {
    return name;
  }
}
