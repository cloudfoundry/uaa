/*
 *  Cloud Foundry
 *  Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *  <p/>
 *  This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *  You may not use this product except in compliance with the License.
 *  <p/>
 *  This product includes a number of subcomponents with
 *  separate copyright notices and license terms. Your use of these
 *  subcomponents is subject to the terms and conditions of the
 *  subcomponent's license, as noted in the LICENSE file
 */
package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;

public class MfaChecker {

    private final IdentityProviderProvisioning providerProvisioning;

    public MfaChecker(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public boolean isMfaEnabled(IdentityZone zone, String originKey) {
        return zone.getConfig().getMfaConfig().isEnabled();
    }

    public boolean isRequired(IdentityZone zone, String originKey) {
        return zone.getConfig().getMfaConfig().getIdentityProviders().contains(originKey);
    }
}
