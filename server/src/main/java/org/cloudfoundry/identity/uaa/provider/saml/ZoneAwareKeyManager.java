/*******************************************************************************
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

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.context.annotation.DependsOn;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.util.Set;

@Component("zoneAwareSamlSpKeyManager")
@DependsOn("identityZoneHolderInitializer")
public class ZoneAwareKeyManager implements KeyManager {
    @Override
    public Credential getCredential(String keyName) {
        return IdentityZoneHolder.getSamlSPKeyManager().getCredential(keyName);
    }

    @Override
    public Credential getDefaultCredential() {
        return IdentityZoneHolder.getSamlSPKeyManager().getDefaultCredential();
    }

    @Override
    public String getDefaultCredentialName() {
        return IdentityZoneHolder.getSamlSPKeyManager().getDefaultCredentialName();
    }

    @Override
    public Set<String> getAvailableCredentials() {
        return IdentityZoneHolder.getSamlSPKeyManager().getAvailableCredentials();
    }

    @Override
    public X509Certificate getCertificate(String alias) {
        return IdentityZoneHolder.getSamlSPKeyManager().getCertificate(alias);
    }

    @Override
    public Iterable<Credential> resolve(CriteriaSet criteria) throws SecurityException {
        return IdentityZoneHolder.getSamlSPKeyManager().resolve(criteria);
    }

    @Override
    public Credential resolveSingle(CriteriaSet criteria) throws SecurityException {
        return IdentityZoneHolder.getSamlSPKeyManager().resolveSingle(criteria);
    }
}
