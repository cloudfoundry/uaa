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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy.Result;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Locks an account out for a configured period based on the number of failed
 * logins since a specific time in the past.
 * <p>
 * Queries the audit service to obtain the relevant data for the user.
 *
 * @author Luke Taylor
 */
public class PeriodLockoutPolicy implements AccountLoginPolicy {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final LoginPolicy loginPolicy;

    public PeriodLockoutPolicy(LoginPolicy loginPolicy) {
        this.loginPolicy = loginPolicy;
    }

    public LockoutPolicy getDefaultLockoutPolicy() {
        return this.loginPolicy.getLockoutPolicyRetriever().getDefaultLockoutPolicy();
    }

    @Override
    public boolean isAllowed(UaaUser user, Authentication a) throws AuthenticationException {
        Result loginResult = loginPolicy.isAllowed(user.getId());
        if (loginResult.isAllowed()) {
            return true;
        }
        logger.warn("User {} and id {} has {} failed user logins within the last checking period.", user.getUsername(), user.getId(), loginResult.getFailureCount());
        return false;
    }
}
