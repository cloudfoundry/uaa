package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.cloudfoundry.identity.uaa.authentication.manager.AccountLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.PeriodLockoutPolicy;
import org.cloudfoundry.identity.uaa.config.LockoutPolicy;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;

/*******************************************************************************
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
@JsonIgnoreProperties(ignoreUnknown = true)
public class UaaIdentityProviderDefinition {

    private PasswordPolicy passwordPolicy;
    private LockoutPolicy lockoutPolicy;

    public UaaIdentityProviderDefinition() {
    }

    public UaaIdentityProviderDefinition(PasswordPolicy passwordPolicy, LockoutPolicy lockoutPolicy) {
        this.passwordPolicy = passwordPolicy;
        this.lockoutPolicy = lockoutPolicy;
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
}
