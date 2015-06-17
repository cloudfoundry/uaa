package org.cloudfoundry.identity.uaa.zone;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
public class UaaIdentityProviderDefinition {

    private PasswordPolicy passwordPolicy = new PasswordPolicy();

    public UaaIdentityProviderDefinition() {
    }

    public UaaIdentityProviderDefinition(PasswordPolicy passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }

    public PasswordPolicy getPasswordPolicy() {
        return passwordPolicy;
    }

    public void setPasswordPolicy(PasswordPolicy passwordPolicy) {
        this.passwordPolicy = passwordPolicy;
    }
}