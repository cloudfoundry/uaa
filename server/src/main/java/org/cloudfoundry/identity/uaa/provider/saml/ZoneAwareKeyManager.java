/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.annotation.DependsOn;
import org.springframework.stereotype.Component;

import java.util.List;

@Component("zoneAwareSamlSpKeyManager")
@DependsOn("identityZoneHolderInitializer")
public class ZoneAwareKeyManager implements SamlKeyManager {
    @Override
    public KeyWithCert getCredential(String keyName) {
        return IdentityZoneHolder.getSamlKeyManager().getCredential(keyName);
    }

    @Override
    public KeyWithCert getDefaultCredential() {
        return IdentityZoneHolder.getSamlKeyManager().getDefaultCredential();
    }

    @Override
    public String getDefaultCredentialName() {
        return IdentityZoneHolder.getSamlKeyManager().getDefaultCredentialName();
    }

    @Override
    public List<KeyWithCert> getAvailableCredentials() {
        return IdentityZoneHolder.getSamlKeyManager().getAvailableCredentials();
    }

    @Override
    public List<String> getAvailableCredentialIds() {
        return IdentityZoneHolder.getSamlKeyManager().getAvailableCredentialIds();
    }
}
