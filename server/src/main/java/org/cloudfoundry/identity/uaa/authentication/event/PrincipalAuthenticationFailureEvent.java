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
package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;

/**
 * Event which indicates that a non-user principal tried to authenticate and
 * failed.
 * 
 * @author Dave Syer
 */
public class PrincipalAuthenticationFailureEvent extends AbstractUaaPrincipalEvent {

    private final String name;

    public PrincipalAuthenticationFailureEvent(String name, UaaAuthenticationDetails details, String zoneId) {
        super(details == null ? UaaAuthenticationDetails.UNKNOWN : details, zoneId);
        this.name = name;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(name, AuditEventType.PrincipalAuthenticationFailure,
                getOrigin(getAuthenticationDetails()));
    }

    public String getName() {
        return name;
    }

}
