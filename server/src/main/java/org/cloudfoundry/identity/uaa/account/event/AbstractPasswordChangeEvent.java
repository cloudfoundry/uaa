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

import java.security.Principal;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 */
abstract class AbstractPasswordChangeEvent extends AbstractUaaEvent {

    private final UaaUser user;

    private final String message;

    public AbstractPasswordChangeEvent(String message, UaaUser user, Authentication authentication, String zoneId) {
        super(authentication, zoneId);
        this.message = message;
        this.user = user;
    }

    public UaaUser getUser() {
        return user;
    }

    public Principal getPrincipal() {
        return getAuthentication();
    }

    public String getMessage() {
        return message;
    }

}
