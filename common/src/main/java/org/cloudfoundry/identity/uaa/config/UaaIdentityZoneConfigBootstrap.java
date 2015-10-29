package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.env.Environment;

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
public class UaaIdentityZoneConfigBootstrap implements InitializingBean {

    private TokenPolicy tokenPolicy;
    private IdentityZoneProvisioning provisioning;

    public UaaIdentityZoneConfigBootstrap(IdentityZoneProvisioning provisioning) {
        this.provisioning = provisioning;
    }

    @Override
    public void afterPropertiesSet() {
        IdentityZone identityZone = provisioning.retrieve(IdentityZone.getUaa().getId());
        UaaIdentityZoneDefinition definition = new UaaIdentityZoneDefinition(tokenPolicy);
        identityZone.setConfig(JsonUtils.writeValueAsString(definition));
        provisioning.update(identityZone);
    }

    public void setTokenPolicy(TokenPolicy tokenPolicy) {
        this.tokenPolicy = tokenPolicy;
    }
}
