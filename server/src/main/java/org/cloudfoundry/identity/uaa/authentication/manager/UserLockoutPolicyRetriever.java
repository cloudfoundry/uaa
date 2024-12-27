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

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;


public class UserLockoutPolicyRetriever implements LockoutPolicyRetriever {

    private final IdentityProviderProvisioning providerProvisioning;

    private LockoutPolicy defaultLockoutPolicy;

    public UserLockoutPolicyRetriever(final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public LockoutPolicy getLockoutPolicy() {
        IdentityProvider idp = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(idp.getConfig(), UaaIdentityProviderDefinition.class);
        if (idpDefinition != null && idpDefinition.getLockoutPolicy() != null) {
            return idpDefinition.getLockoutPolicy();
        }
        return defaultLockoutPolicy;
    }

    @Override
    public LockoutPolicy getDefaultLockoutPolicy() {
        return defaultLockoutPolicy;
    }

    @Override
    public void setDefaultLockoutPolicy(LockoutPolicy defaultLockoutPolicy) {
        this.defaultLockoutPolicy = defaultLockoutPolicy;
    }
}
