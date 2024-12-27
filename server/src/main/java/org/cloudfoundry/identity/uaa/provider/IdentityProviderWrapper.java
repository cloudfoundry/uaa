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

package org.cloudfoundry.identity.uaa.provider;

public class IdentityProviderWrapper<T extends AbstractIdentityProviderDefinition> {
    final IdentityProvider<T> provider;
    boolean override = true;

    public IdentityProviderWrapper(IdentityProvider<T> provider) {
        this.provider = provider;
    }

    public IdentityProvider<T> getProvider() {
        return provider;
    }

    public boolean isOverride() {
        return override;
    }

    public void setOverride(boolean override) {
        this.override = override;
    }
}
