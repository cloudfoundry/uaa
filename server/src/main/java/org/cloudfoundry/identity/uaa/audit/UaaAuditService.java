package org.cloudfoundry.identity.uaa.audit;

import java.util.List;

/**
 * Service interface which handles the different types of audit event raised by the system.
 *
 * @author Luke Talyor
 * @author Dave Syer
 */
public interface UaaAuditService {

  /**
   * Find audit events relating to the specified principal since the time provided.
   *
   * @param principal the principal name to search for
   * @param after epoch in milliseconds
   * @return audit events relating to the principal
   */
  List<AuditEvent> find(String principal, long after, String zoneId);

  /**
   * Log an event.
   *
   * @param auditEvent the audit event to log
   */
  void log(AuditEvent auditEvent, String zoneId);
}
