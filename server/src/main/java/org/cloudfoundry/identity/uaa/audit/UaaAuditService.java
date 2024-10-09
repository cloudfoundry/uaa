/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.audit;

import java.util.List;

/**
 * Service interface which handles the different types of audit event raised by
 * the system.
 *
 * @author Luke Talyor
 * @author Dave Syer
 */
public interface UaaAuditService {

    /**
     * Find audit events relating to the specified principal since the time
     * provided.
     *
     * @param principal the principal name to search for
     * @param after epoch in milliseconds
     * @param zoneId
     * @return audit events relating to the principal
     */
    List<AuditEvent> find(String principal, long after, String zoneId);

    /**
     * Log an event.
     *
     * @param auditEvent the audit event to log
     * @param zoneId
     */
    void log(AuditEvent auditEvent, String zoneId);

}
