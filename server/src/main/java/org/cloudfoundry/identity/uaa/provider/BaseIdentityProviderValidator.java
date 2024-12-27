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

import java.util.Optional;

public abstract class BaseIdentityProviderValidator implements IdentityProviderConfigValidator {

    @Override
    public void validate(IdentityProvider<? extends AbstractIdentityProviderDefinition> provider) {
        AbstractIdentityProviderDefinition definition = Optional.ofNullable(provider)
                .orElseThrow(() -> new IllegalArgumentException("Provider cannot be null"))
                .getConfig();
        validate(definition);

    }

    public abstract void validate(AbstractIdentityProviderDefinition definition);
}
