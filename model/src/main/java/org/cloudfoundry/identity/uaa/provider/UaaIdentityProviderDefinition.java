/*
 * *****************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaIdentityProviderDefinition extends AbstractIdentityProviderDefinition {

    private PasswordPolicy passwordPolicy;
    private LockoutPolicy lockoutPolicy;
    private boolean disableInternalUserManagement;

    public UaaIdentityProviderDefinition() {
    }

    public UaaIdentityProviderDefinition(PasswordPolicy passwordPolicy, LockoutPolicy lockoutPolicy) {
        this(passwordPolicy, lockoutPolicy, false);
    }

    public UaaIdentityProviderDefinition(PasswordPolicy passwordPolicy, LockoutPolicy lockoutPolicy, boolean disableInternalUserManagement) {
        this.passwordPolicy = passwordPolicy;
        this.lockoutPolicy = lockoutPolicy;
        this.disableInternalUserManagement = disableInternalUserManagement;
    }

    public PasswordPolicy getPasswordPolicy() {
        return passwordPolicy;
    }

    public void setPasswordPolicy(PasswordPolicy passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    public LockoutPolicy getLockoutPolicy() {
        return lockoutPolicy;
    }

    public void setLockoutPolicy(LockoutPolicy lockoutPolicy) {
        this.lockoutPolicy = lockoutPolicy;
    }

    public boolean isDisableInternalUserManagement() {
        return disableInternalUserManagement;
    }

    public void setDisableInternalUserManagement(boolean disableInternalUserManagement) {
        this.disableInternalUserManagement = disableInternalUserManagement;
    }
}
