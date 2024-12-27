package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.context.ApplicationEvent;

/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
public abstract class AuthEvent extends ApplicationEvent {

    private boolean userModified = true;

    public AuthEvent(UaaUser user, boolean userUpdated) {
        super(user);
        this.userModified = userUpdated;
    }

    public UaaUser getUser() {
        return (UaaUser) source;
    }

    public boolean isUserModified() {
        return userModified;
    }
}
