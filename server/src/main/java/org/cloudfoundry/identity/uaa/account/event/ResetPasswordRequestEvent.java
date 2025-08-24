/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.springframework.security.core.Authentication;

public class ResetPasswordRequestEvent extends AbstractUaaEvent {

    private final String code;
    private final String email;

    public ResetPasswordRequestEvent(String username, String email, String code, Authentication authentication, String zoneId) {
        super(username, authentication, zoneId);
        this.code = code;
        this.email = email;
    }

    @Override
    public AuditEvent getAuditEvent() {
        return createAuditRecord(getSource().toString(), AuditEventType.PasswordResetRequest, getOrigin(getAuthentication()), email);
    }

    public String getCode() {
        return code;
    }

    public String getEmail() {
        return email;
    }
}
