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

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ExternalGroupAuthorizationEvent extends AuthEvent {

    public Collection<? extends GrantedAuthority> getExternalAuthorities() {
        return externalAuthorities;
    }

    private Collection<? extends GrantedAuthority> externalAuthorities;

    private boolean addGroups = false;

    public ExternalGroupAuthorizationEvent(UaaUser user, boolean userModified, Collection<? extends GrantedAuthority> externalAuthorities, boolean addGroups) {
        super(user, userModified);
        this.addGroups = addGroups;
        this.externalAuthorities = externalAuthorities;
    }

    public boolean isAddGroups() {
        return addGroups;
    }
}
