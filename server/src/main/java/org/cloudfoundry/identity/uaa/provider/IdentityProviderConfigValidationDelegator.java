/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */
package org.cloudfoundry.identity.uaa.provider;

import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

public class IdentityProviderConfigValidationDelegator implements IdentityProviderConfigValidator {
    private Map<String, IdentityProviderConfigValidator> delegates;

    public void setDelegates(Map<String, IdentityProviderConfigValidator> delegates) {
        this.delegates = delegates;
    }

    @Override
    public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        if (provider == null) {
            throw new IllegalArgumentException("Provider cannot be null");
        }
        String type = provider.getType();
        switch (type) {
            case OAUTH20:
            case OIDC10:
                delegates.get("xoauth").validate(provider);
                break;
            case UAA:
                delegates.get(UAA).validate(provider);
                break;
            case LDAP:
                delegates.get(LDAP).validate(provider);
                break;
        }
    }
}
