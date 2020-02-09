/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */
package org.cloudfoundry.identity.uaa.authentication.manager;


import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class CheckIdpEnabledAuthenticationManager implements AuthenticationManager {

    private final String origin;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final AuthenticationManager delegate;

    public CheckIdpEnabledAuthenticationManager(AuthenticationManager delegate, String origin, final @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning identityProviderProvisioning) {
        this.origin = origin;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.delegate = delegate;
    }

    public String getOrigin() {
        return origin;
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        try {
            IdentityProvider idp = identityProviderProvisioning.retrieveByOriginIgnoreActiveFlag(getOrigin(), IdentityZoneHolder.get().getId());
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider \"" + idp.getName() + "\" has been disabled by administrator.");
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("Unable to find identity provider for origin: " + getOrigin());
        }
        return delegate.authenticate(authentication);
    }
}
