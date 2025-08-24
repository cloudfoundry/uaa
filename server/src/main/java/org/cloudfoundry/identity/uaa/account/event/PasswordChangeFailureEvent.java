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

package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 * 
 */
public class PasswordChangeFailureEvent extends AbstractPasswordChangeEvent {

    public PasswordChangeFailureEvent(String message, UaaUser user, Authentication principal, String zoneId) {
        super(message, user, principal, zoneId);
    }

    @Override
    public AuditEvent getAuditEvent() {
        UaaUser user = getUser();
        if (user == null) {
            return createAuditRecord(getPrincipal().getName(), AuditEventType.PasswordChangeFailure,
                    getOrigin(getPrincipal()), getMessage());
        } else {
            return createAuditRecord(user.getUsername(), AuditEventType.PasswordChangeFailure,
                    getOrigin(getPrincipal()), getMessage());
        }
    }

}
