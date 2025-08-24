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

package org.cloudfoundry.identity.uaa.provider.ldap;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.BaseIdentityProviderValidator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.springframework.stereotype.Component;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;

@Component
public class LdapIdentityProviderConfigValidator extends BaseIdentityProviderValidator {

    @Override
    public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        super.validate(provider);
        if (!LDAP.equals(provider.getOriginKey())) {
            throw new IllegalArgumentException("LDAP provider originKey must be set to '%s'".formatted(LDAP));
        }
    }

    @Override
    public void validate(AbstractIdentityProviderDefinition definition) {
        //not yet implemented
    }
}
